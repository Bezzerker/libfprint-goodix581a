/*
 * Minimal SIFT keypoint extraction and geometric matching for small
 * fingerprint images. The SIFT part follows OpenCV's implementation
 * (Lowe 2004) so that results match cv2.SIFT closely; matching is a ratio
 * test plus an exhaustive two-point rigid-transform consensus.
 *
 * The SIFT pipeline is a port of OpenCV modules/features2d/src/sift.*
 * (Apache License 2.0):
 *   Copyright (c) 2006-2010, Rob Hess <hess@eecs.oregonstate.edu>
 *   Copyright (C) 2009, Willow Garage Inc., all rights reserved.
 *   Copyright (C) 2020, Intel Corporation, all rights reserved.
 * See NOTICE. The SIFT patent (US 6,711,293) expired in March 2020.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "sigmatch.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

/* bicubic upscale of the input before SIFT; x2 separated fingers best */
#ifndef UPSCALE
#define UPSCALE 2
#endif
#define N_LAYERS 3
#define SIGMA 1.6f
#define INIT_SIGMA 0.5f
#ifndef CONTRAST_THR
#define CONTRAST_THR 0.04f
#endif
#ifndef EDGE_THR
#define EDGE_THR 10.0f
#endif
#define IMG_BORDER 5
#define MAX_INTERP_STEPS 5
#define ORI_BINS 36
#define ORI_PEAK_RATIO 0.8f
#define ORI_SIG_FCTR 1.5f
#define ORI_RADIUS (3 * ORI_SIG_FCTR)
#define DESCR_WIDTH 4
#define DESCR_BINS 8
#define DESCR_SCL_FCTR 3.0f
#define DESCR_MAG_THR 0.2f
#define INT_DESCR_FCTR 512.0f
#define MAX_OCTAVES 8

#ifndef RATIO
#define RATIO 0.75f
#endif
/* inlier distance, input pixels */
#ifndef MATCH_TOL
#define MATCH_TOL 2.0f
#endif
/* shortest point pair used to hypothesise a transform, input pixels */
#ifndef MIN_PAIR_DIST
#define MIN_PAIR_DIST 3.0f
#endif
#ifndef MAX_SCALE_DEV
#define MAX_SCALE_DEV 0.15f
#endif
/* keypoint orientation change vs transform rotation, degrees */
#ifndef ANGLE_TOL
#define ANGLE_TOL 20.0f
#endif

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

typedef struct
{
  int    w, h;
  float *d;
} Img;

typedef struct
{
  float x, y;     /* in the doubled-upscaled base image */
  int   octave, layer;
  float scl_octv; /* scale within the octave */
  float size;
  float response;
  float angle;
} RawKp;

typedef struct
{
  RawKp *v;
  int    n, cap;
} KpList;

static Img
img_new (int w, int h)
{
  Img im = { w, h, calloc ((size_t) w * h, sizeof (float)) };

  return im;
}

#define AT(im, x, y) ((im).d[(y) * (im).w + (x)])

static int
clampi (int v, int lo, int hi)
{
  return v < lo ? lo : v > hi ? hi : v;
}

static float
cubic_w (float x)
{
  const float a = -0.75f; /* same kernel as OpenCV INTER_CUBIC */

  x = fabsf (x);
  if (x <= 1)
    return ((a + 2) * x - (a + 3)) * x * x + 1;
  if (x < 2)
    return ((a * x - 5 * a) * x + 8 * a) * x - 4 * a;
  return 0;
}

/* resize by an integer factor; cubic or linear, pixel-centre aligned */
static Img
resize (Img src, int f, int cubic)
{
  Img dst = img_new (src.w * f, src.h * f);
  Img tmp = img_new (dst.w, src.h);
  int taps = cubic ? 2 : 1;

  for (int y = 0; y < src.h; y++)
    for (int x = 0; x < dst.w; x++)
      {
        float sx = (x + 0.5f) / f - 0.5f, acc = 0, wsum = 0;
        int x0 = (int) floorf (sx);
        for (int k = x0 - taps + 1; k <= x0 + taps; k++)
          {
            float w = cubic ? cubic_w (sx - k) : fmaxf (0, 1 - fabsf (sx - k));
            acc += w * AT (src, clampi (k, 0, src.w - 1), y);
            wsum += w;
          }
        AT (tmp, x, y) = acc / wsum;
      }
  for (int y = 0; y < dst.h; y++)
    for (int x = 0; x < dst.w; x++)
      {
        float sy = (y + 0.5f) / f - 0.5f, acc = 0, wsum = 0;
        int y0 = (int) floorf (sy);
        for (int k = y0 - taps + 1; k <= y0 + taps; k++)
          {
            float w = cubic ? cubic_w (sy - k) : fmaxf (0, 1 - fabsf (sy - k));
            acc += w * AT (tmp, x, clampi (k, 0, src.h - 1));
            wsum += w;
          }
        AT (dst, x, y) = acc / wsum;
      }
  free (tmp.d);
  return dst;
}

static int
reflect101 (int i, int n)
{
  if (n == 1)
    return 0;
  while (i < 0 || i >= n)
    i = i < 0 ? -i : 2 * n - 2 - i;
  return i;
}

static Img
blur (Img src, float sigma)
{
  int ksize = ((int) lroundf (sigma * 8 + 1)) | 1;
  int r = ksize / 2;
  float *k = malloc (sizeof (float) * ksize), ksum = 0;
  Img tmp = img_new (src.w, src.h), dst = img_new (src.w, src.h);

  for (int i = 0; i < ksize; i++)
    ksum += k[i] = expf (-(float) (i - r) * (i - r) / (2 * sigma * sigma));
  for (int i = 0; i < ksize; i++)
    k[i] /= ksum;

  for (int y = 0; y < src.h; y++)
    for (int x = 0; x < src.w; x++)
      {
        float acc = 0;
        for (int i = 0; i < ksize; i++)
          acc += k[i] * AT (src, reflect101 (x + i - r, src.w), y);
        AT (tmp, x, y) = acc;
      }
  for (int y = 0; y < src.h; y++)
    for (int x = 0; x < src.w; x++)
      {
        float acc = 0;
        for (int i = 0; i < ksize; i++)
          acc += k[i] * AT (tmp, x, reflect101 (y + i - r, src.h));
        AT (dst, x, y) = acc;
      }
  free (k);
  free (tmp.d);
  return dst;
}

static Img
half (Img src)
{
  Img dst = img_new (src.w / 2, src.h / 2);

  for (int y = 0; y < dst.h; y++)
    for (int x = 0; x < dst.w; x++)
      AT (dst, x, y) = AT (src, 2 * x, 2 * y);
  return dst;
}

static void
kp_push (KpList *l, RawKp kp)
{
  if (l->n == l->cap)
    {
      l->cap = l->cap ? l->cap * 2 : 256;
      l->v = realloc (l->v, sizeof (RawKp) * l->cap);
    }
  l->v[l->n++] = kp;
}

/* 3x3 linear solve by Cramer's rule; returns 0 if singular */
static int
solve3 (const float H[3][3], const float b[3], float x[3])
{
  float det = H[0][0] * (H[1][1] * H[2][2] - H[1][2] * H[2][1])
            - H[0][1] * (H[1][0] * H[2][2] - H[1][2] * H[2][0])
            + H[0][2] * (H[1][0] * H[2][1] - H[1][1] * H[2][0]);

  if (fabsf (det) < 1e-12f)
    return 0;
  for (int c = 0; c < 3; c++)
    {
      float M[3][3];
      memcpy (M, H, sizeof (M));
      for (int r = 0; r < 3; r++)
        M[r][c] = b[r];
      x[c] = (M[0][0] * (M[1][1] * M[2][2] - M[1][2] * M[2][1])
            - M[0][1] * (M[1][0] * M[2][2] - M[1][2] * M[2][0])
            + M[0][2] * (M[1][0] * M[2][1] - M[1][1] * M[2][0])) / det;
    }
  return 1;
}

/* sub-pixel refinement and contrast / edge rejection (OpenCV adjustLocalExtrema) */
static int
adjust_extremum (Img *dog, int octave, int *layer, int *r, int *c, RawKp *kp)
{
  const float img_scale = 1.f / 255, deriv = img_scale * 0.5f;
  const float second = img_scale, cross = img_scale * 0.25f;
  float xi = 0, xr = 0, xc = 0, dD[3];
  int i;

  for (i = 0; i < MAX_INTERP_STEPS; i++)
    {
      Img im = dog[*layer], prv = dog[*layer - 1], nxt = dog[*layer + 1];
      float v2 = AT (im, *c, *r) * 2, H[3][3], X[3], b[3];

      dD[0] = (AT (im, *c + 1, *r) - AT (im, *c - 1, *r)) * deriv;
      dD[1] = (AT (im, *c, *r + 1) - AT (im, *c, *r - 1)) * deriv;
      dD[2] = (AT (nxt, *c, *r) - AT (prv, *c, *r)) * deriv;
      H[0][0] = (AT (im, *c + 1, *r) + AT (im, *c - 1, *r) - v2) * second;
      H[1][1] = (AT (im, *c, *r + 1) + AT (im, *c, *r - 1) - v2) * second;
      H[2][2] = (AT (nxt, *c, *r) + AT (prv, *c, *r) - v2) * second;
      H[0][1] = H[1][0] = (AT (im, *c + 1, *r + 1) - AT (im, *c - 1, *r + 1)
                         - AT (im, *c + 1, *r - 1) + AT (im, *c - 1, *r - 1)) * cross;
      H[0][2] = H[2][0] = (AT (nxt, *c + 1, *r) - AT (nxt, *c - 1, *r)
                         - AT (prv, *c + 1, *r) + AT (prv, *c - 1, *r)) * cross;
      H[1][2] = H[2][1] = (AT (nxt, *c, *r + 1) - AT (nxt, *c, *r - 1)
                         - AT (prv, *c, *r + 1) + AT (prv, *c, *r - 1)) * cross;
      for (int k = 0; k < 3; k++)
        b[k] = -dD[k];
      if (!solve3 (H, b, X))
        return 0;
      xc = X[0], xr = X[1], xi = X[2];
      if (fabsf (xi) < 0.5f && fabsf (xr) < 0.5f && fabsf (xc) < 0.5f)
        break;
      if (fabsf (xi) > (float) (INT32_MAX / 3) || fabsf (xr) > (float) (INT32_MAX / 3) ||
          fabsf (xc) > (float) (INT32_MAX / 3))
        return 0;
      *c += (int) lroundf (xc);
      *r += (int) lroundf (xr);
      *layer += (int) lroundf (xi);
      if (*layer < 1 || *layer > N_LAYERS || *c < IMG_BORDER || *c >= dog[0].w - IMG_BORDER ||
          *r < IMG_BORDER || *r >= dog[0].h - IMG_BORDER)
        return 0;
    }
  if (i >= MAX_INTERP_STEPS)
    return 0;

  {
    Img im = dog[*layer], prv = dog[*layer - 1], nxt = dog[*layer + 1];
    float t, contr, v2 = AT (im, *c, *r) * 2, dxx, dyy, dxy, tr, det;

    dD[0] = (AT (im, *c + 1, *r) - AT (im, *c - 1, *r)) * deriv;
    dD[1] = (AT (im, *c, *r + 1) - AT (im, *c, *r - 1)) * deriv;
    dD[2] = (AT (nxt, *c, *r) - AT (prv, *c, *r)) * deriv;
    t = dD[0] * xc + dD[1] * xr + dD[2] * xi;
    contr = AT (im, *c, *r) * img_scale + t * 0.5f;
    if (fabsf (contr) * N_LAYERS < CONTRAST_THR)
      return 0;

    dxx = (AT (im, *c + 1, *r) + AT (im, *c - 1, *r) - v2) * second;
    dyy = (AT (im, *c, *r + 1) + AT (im, *c, *r - 1) - v2) * second;
    dxy = (AT (im, *c + 1, *r + 1) - AT (im, *c - 1, *r + 1)
         - AT (im, *c + 1, *r - 1) + AT (im, *c - 1, *r - 1)) * cross;
    tr = dxx + dyy;
    det = dxx * dyy - dxy * dxy;
    if (det <= 0 || tr * tr * EDGE_THR >= (EDGE_THR + 1) * (EDGE_THR + 1) * det)
      return 0;

    kp->x = (*c + xc) * (1 << octave);
    kp->y = (*r + xr) * (1 << octave);
    kp->octave = octave;
    kp->layer = *layer;
    kp->scl_octv = SIGMA * powf (2.f, (*layer + xi) / N_LAYERS);
    kp->size = kp->scl_octv * (1 << octave) * 2;
    kp->response = fabsf (contr);
  }
  return 1;
}

static int
orientations (Img g, int cx, int cy, float scl_octv, float out[ORI_BINS])
{
  int radius = (int) lroundf (ORI_RADIUS * scl_octv), n = 0;
  float sigma = ORI_SIG_FCTR * scl_octv, hist[ORI_BINS + 4] = { 0 }, *h = hist + 2;
  float smooth[ORI_BINS], maxv = 0;

  for (int i = -radius; i <= radius; i++)
    {
      int y = cy + i;
      if (y <= 0 || y >= g.h - 1)
        continue;
      for (int j = -radius; j <= radius; j++)
        {
          int x = cx + j;
          float dx, dy, w, ang;
          int bin;
          if (x <= 0 || x >= g.w - 1)
            continue;
          dx = AT (g, x + 1, y) - AT (g, x - 1, y);
          dy = AT (g, x, y - 1) - AT (g, x, y + 1);
          w = expf (-(i * i + j * j) / (2 * sigma * sigma));
          ang = atan2f (dy, dx) * (float) (180 / M_PI);
          if (ang < 0)
            ang += 360;
          bin = (int) lroundf (ang * ORI_BINS / 360);
          if (bin >= ORI_BINS)
            bin -= ORI_BINS;
          h[bin] += w * sqrtf (dx * dx + dy * dy);
        }
    }
  h[-1] = h[ORI_BINS - 1];
  h[-2] = h[ORI_BINS - 2];
  h[ORI_BINS] = h[0];
  h[ORI_BINS + 1] = h[1];
  for (int i = 0; i < ORI_BINS; i++)
    {
      smooth[i] = (h[i - 2] + h[i + 2]) * (1.f / 16) + (h[i - 1] + h[i + 1]) * (4.f / 16) +
                  h[i] * (6.f / 16);
      maxv = fmaxf (maxv, smooth[i]);
    }
  for (int j = 0; j < ORI_BINS; j++)
    {
      int l = j > 0 ? j - 1 : ORI_BINS - 1, r = j < ORI_BINS - 1 ? j + 1 : 0;
      if (smooth[j] > smooth[l] && smooth[j] > smooth[r] && smooth[j] >= maxv * ORI_PEAK_RATIO)
        {
          float bin = j + 0.5f * (smooth[l] - smooth[r]) /
                      (smooth[l] - 2 * smooth[j] + smooth[r]);
          float ang;
          bin = bin < 0 ? ORI_BINS + bin : bin >= ORI_BINS ? bin - ORI_BINS : bin;
          ang = 360.f - (360.f / ORI_BINS) * bin;
          if (fabsf (ang - 360.f) < 1e-5f)
            ang = 0;
          out[n++] = ang;
        }
    }
  return n;
}

static void
descriptor (Img g, float px, float py, float ori, float scl, uint8_t out[SIGM_DESC_LEN])
{
  const int d = DESCR_WIDTH, n = DESCR_BINS;
  int ptx = (int) lroundf (px), pty = (int) lroundf (py);
  float cos_t = cosf (ori * (float) (M_PI / 180)), sin_t = sinf (ori * (float) (M_PI / 180));
  float bins_per_rad = n / 360.f, exp_scale = -1.f / (d * d * 0.5f);
  float hist_width = DESCR_SCL_FCTR * scl;
  int radius = (int) lroundf (hist_width * 1.4142135623730951f * (d + 1) * 0.5f);
  float hist[(DESCR_WIDTH + 2) * (DESCR_WIDTH + 2) * (DESCR_BINS + 2)] = { 0 };
  float dst[SIGM_DESC_LEN], nrm2 = 0, thr;
  int maxr = (int) sqrtf ((float) g.w * g.w + (float) g.h * g.h);

  if (radius > maxr)
    radius = maxr;
  cos_t /= hist_width;
  sin_t /= hist_width;

  for (int i = -radius; i <= radius; i++)
    for (int j = -radius; j <= radius; j++)
      {
        float c_rot = j * cos_t - i * sin_t, r_rot = j * sin_t + i * cos_t;
        float rbin = r_rot + d / 2 - 0.5f, cbin = c_rot + d / 2 - 0.5f;
        int r = pty + i, c = ptx + j;
        float dx, dy, w, gori, mag, obin;
        int r0, c0, o0;
        float v_r1, v_r0, v_rc11, v_rc10, v_rc01, v_rc00;

        if (!(rbin > -1 && rbin < d && cbin > -1 && cbin < d && r > 0 && r < g.h - 1 &&
              c > 0 && c < g.w - 1))
          continue;
        dx = AT (g, c + 1, r) - AT (g, c - 1, r);
        dy = AT (g, c, r - 1) - AT (g, c, r + 1);
        w = expf ((c_rot * c_rot + r_rot * r_rot) * exp_scale);
        gori = atan2f (dy, dx) * (float) (180 / M_PI);
        if (gori < 0)
          gori += 360;
        mag = sqrtf (dx * dx + dy * dy) * w;
        obin = (gori - ori) * bins_per_rad;

        r0 = (int) floorf (rbin);
        c0 = (int) floorf (cbin);
        o0 = (int) floorf (obin);
        rbin -= r0;
        cbin -= c0;
        obin -= o0;
        if (o0 < 0)
          o0 += n;
        if (o0 >= n)
          o0 -= n;

        v_r1 = mag * rbin, v_r0 = mag - v_r1;
        v_rc11 = v_r1 * cbin, v_rc10 = v_r1 - v_rc11;
        v_rc01 = v_r0 * cbin, v_rc00 = v_r0 - v_rc01;
        {
          float v_rco111 = v_rc11 * obin, v_rco110 = v_rc11 - v_rco111;
          float v_rco101 = v_rc10 * obin, v_rco100 = v_rc10 - v_rco101;
          float v_rco011 = v_rc01 * obin, v_rco010 = v_rc01 - v_rco011;
          float v_rco001 = v_rc00 * obin, v_rco000 = v_rc00 - v_rco001;
          int idx = ((r0 + 1) * (d + 2) + c0 + 1) * (n + 2) + o0;
          hist[idx] += v_rco000;
          hist[idx + 1] += v_rco001;
          hist[idx + (n + 2)] += v_rco010;
          hist[idx + (n + 3)] += v_rco011;
          hist[idx + (d + 2) * (n + 2)] += v_rco100;
          hist[idx + (d + 2) * (n + 2) + 1] += v_rco101;
          hist[idx + (d + 3) * (n + 2)] += v_rco110;
          hist[idx + (d + 3) * (n + 2) + 1] += v_rco111;
        }
      }

  for (int i = 0; i < d; i++)
    for (int j = 0; j < d; j++)
      {
        int idx = ((i + 1) * (d + 2) + (j + 1)) * (n + 2);
        hist[idx] += hist[idx + n];
        hist[idx + 1] += hist[idx + n + 1];
        for (int k = 0; k < n; k++)
          dst[(i * d + j) * n + k] = hist[idx + k];
      }
  for (int k = 0; k < SIGM_DESC_LEN; k++)
    nrm2 += dst[k] * dst[k];
  thr = sqrtf (nrm2) * DESCR_MAG_THR;
  nrm2 = 0;
  for (int k = 0; k < SIGM_DESC_LEN; k++)
    {
      dst[k] = fminf (dst[k], thr);
      nrm2 += dst[k] * dst[k];
    }
  nrm2 = INT_DESCR_FCTR / fmaxf (sqrtf (nrm2), 1.1920929e-07f);
  for (int k = 0; k < SIGM_DESC_LEN; k++)
    {
      int v = (int) lroundf (dst[k] * nrm2);
      out[k] = v < 0 ? 0 : v > 255 ? 255 : v;
    }
}

typedef struct
{
  float        response;
  SigmKeypoint kp;
} Ranked;

static int
cmp_ranked (const void *a, const void *b)
{
  float ra = ((const Ranked *) a)->response, rb = ((const Ranked *) b)->response;

  return ra < rb ? 1 : ra > rb ? -1 : 0;
}

SigmFeatures *
sigm_extract (const uint8_t *pix, int width, int height, int max_keypoints)
{
  Img src = img_new (width, height), up, base, gauss[MAX_OCTAVES][N_LAYERS + 3];
  Img dog[MAX_OCTAVES][N_LAYERS + 2];
  float sig[N_LAYERS + 3], k = powf (2.f, 1.f / N_LAYERS);
  int n_oct, threshold = (int) floorf (0.5f * CONTRAST_THR / N_LAYERS * 255);
  KpList raw = { 0 };
  Ranked *ranked = NULL;
  int n_ranked = 0, cap_ranked = 0;
  SigmFeatures *f;

  for (int i = 0; i < width * height; i++)
    src.d[i] = pix[i];
  up = resize (src, UPSCALE, 1);
  {
    /* OpenCV doubles the image (first octave -1) */
    Img dbl = resize (up, 2, 0);
    float sig_diff = sqrtf (fmaxf (SIGMA * SIGMA - INIT_SIGMA * INIT_SIGMA * 4, 0.01f));
    base = blur (dbl, sig_diff);
    free (dbl.d);
  }
  free (src.d);
  free (up.d);

  n_oct = (int) lroundf (log2f ((float) (base.w < base.h ? base.w : base.h)) - 2) + 1;
  if (n_oct > MAX_OCTAVES)
    n_oct = MAX_OCTAVES;

  sig[0] = SIGMA;
  for (int i = 1; i < N_LAYERS + 3; i++)
    {
      float prev = powf (k, (float) (i - 1)) * SIGMA, total = prev * k;
      sig[i] = sqrtf (total * total - prev * prev);
    }

  for (int o = 0; o < n_oct; o++)
    {
      gauss[o][0] = o == 0 ? base : half (gauss[o - 1][N_LAYERS]);
      for (int i = 1; i < N_LAYERS + 3; i++)
        gauss[o][i] = blur (gauss[o][i - 1], sig[i]);
      for (int i = 0; i < N_LAYERS + 2; i++)
        {
          dog[o][i] = img_new (gauss[o][0].w, gauss[o][0].h);
          for (int p = 0; p < dog[o][i].w * dog[o][i].h; p++)
            dog[o][i].d[p] = gauss[o][i + 1].d[p] - gauss[o][i].d[p];
        }
    }

  for (int o = 0; o < n_oct; o++)
    for (int i = 1; i <= N_LAYERS; i++)
      {
        Img cur = dog[o][i];
        for (int r = IMG_BORDER; r < cur.h - IMG_BORDER; r++)
          for (int c = IMG_BORDER; c < cur.w - IMG_BORDER; c++)
            {
              float v = AT (cur, c, r);
              int is_ext = 1;
              if (fabsf (v) <= threshold)
                continue;
              for (int di = -1; di <= 1 && is_ext; di++)
                for (int dy = -1; dy <= 1 && is_ext; dy++)
                  for (int dx = -1; dx <= 1 && is_ext; dx++)
                    {
                      float nv;
                      if (!di && !dy && !dx)
                        continue;
                      nv = AT (dog[o][i + di], c + dx, r + dy);
                      if ((v > 0 && nv > v) || (v < 0 && nv < v))
                        is_ext = 0;
                    }
              if (is_ext)
                {
                  int layer = i, rr = r, cc = c;
                  RawKp kp;
                  if (adjust_extremum (dog[o], o, &layer, &rr, &cc, &kp))
                    {
                      float angs[ORI_BINS];
                      int na = orientations (gauss[o][layer], cc, rr, kp.scl_octv, angs);
                      for (int a = 0; a < na; a++)
                        {
                          kp.angle = angs[a];
                          kp_push (&raw, kp);
                        }
                    }
                }
            }
      }

  for (int i = 0; i < raw.n; i++)
    {
      RawKp *kp = &raw.v[i];
      float scale = 1.f / (1 << kp->octave);
      Ranked rk;
      if (n_ranked == cap_ranked)
        {
          cap_ranked = cap_ranked ? cap_ranked * 2 : 256;
          ranked = realloc (ranked, sizeof (Ranked) * cap_ranked);
        }
      descriptor (gauss[kp->octave][kp->layer], kp->x * scale, kp->y * scale,
                  360.f - kp->angle, kp->size * 0.5f * scale, rk.kp.desc);
      /* back to input pixels: undo the x2 doubling and the bicubic upscale */
      rk.kp.angle = kp->angle;
      rk.kp.x = kp->x * 0.5f / UPSCALE;
      rk.kp.y = kp->y * 0.5f / UPSCALE;
      rk.response = kp->response;
      ranked[n_ranked++] = rk;
    }
  qsort (ranked, n_ranked, sizeof (Ranked), cmp_ranked);
  if (max_keypoints > 0 && n_ranked > max_keypoints)
    n_ranked = max_keypoints;

  f = calloc (1, sizeof (*f));
  f->n = n_ranked;
  f->kp = malloc (sizeof (SigmKeypoint) * (n_ranked ? n_ranked : 1));
  for (int i = 0; i < n_ranked; i++)
    f->kp[i] = ranked[i].kp;

  free (ranked);
  free (raw.v);
  for (int o = 0; o < n_oct; o++)
    {
      for (int i = 0; i < N_LAYERS + 3; i++)
        free (gauss[o][i].d);
      for (int i = 0; i < N_LAYERS + 2; i++)
        free (dog[o][i].d);
    }
  return f;
}

void
sigm_features_free (SigmFeatures *f)
{
  if (!f)
    return;
  free (f->kp);
  free (f);
}

static int
dist2 (const uint8_t *a, const uint8_t *b)
{
  int s = 0;

  for (int i = 0; i < SIGM_DESC_LEN; i++)
    {
      int d = a[i] - b[i];
      s += d * d;
    }
  return s;
}

static float
wrap180 (float a)
{
  while (a > 180)
    a -= 360;
  while (a <= -180)
    a += 360;
  return a;
}

int
sigm_match (const SigmFeatures *probe, const SigmFeatures *gallery, int *candidates)
{
  float (*pa)[3], (*pb)[3];
  int *gj, *used, n = 0, best = 0;

  if (candidates)
    *candidates = 0;
  if (probe->n < 2 || gallery->n < 2)
    return 0;
  pa = malloc (sizeof (*pa) * probe->n);
  pb = malloc (sizeof (*pb) * probe->n);
  gj = malloc (sizeof (int) * probe->n);
  used = calloc (gallery->n, sizeof (int));

  for (int i = 0; i < probe->n; i++)
    {
      int d1 = 1 << 30, d2 = 1 << 30, bj = -1;
      for (int j = 0; j < gallery->n; j++)
        {
          int d = dist2 (probe->kp[i].desc, gallery->kp[j].desc);
          if (d < d1)
            d2 = d1, d1 = d, bj = j;
          else if (d < d2)
            d2 = d;
        }
      /* Lowe ratio test on distances: d1 < RATIO * d2 */
      if (bj >= 0 && (float) d1 < RATIO * RATIO * (float) d2)
        {
          pa[n][0] = probe->kp[i].x, pa[n][1] = probe->kp[i].y, pa[n][2] = probe->kp[i].angle;
          pb[n][0] = gallery->kp[bj].x, pb[n][1] = gallery->kp[bj].y, pb[n][2] = gallery->kp[bj].angle;
          gj[n++] = bj;
        }
    }

  if (candidates)
    *candidates = n;

  /* exhaustive two-point hypotheses of a near-rigid transform */
  for (int i = 0; i < n; i++)
    for (int j = i + 1; j < n; j++)
      {
        float vax = pa[j][0] - pa[i][0], vay = pa[j][1] - pa[i][1];
        float vbx = pb[j][0] - pb[i][0], vby = pb[j][1] - pb[i][1];
        float la = sqrtf (vax * vax + vay * vay), lb = sqrtf (vbx * vbx + vby * vby);
        float s, cs, sn, rot;
        int inl = 0;
        if (gj[i] == gj[j] || la < MIN_PAIR_DIST || fabsf (lb / la - 1) > MAX_SCALE_DEV)
          continue;
        /* rotation+scale as a complex ratio vb / va */
        s = 1.f / (la * la);
        cs = (vbx * vax + vby * vay) * s;
        sn = (vby * vax - vbx * vay) * s;
        rot = atan2f (sn, cs) * (float) (180 / M_PI);
        memset (used, 0, sizeof (int) * gallery->n);
        for (int m = 0; m < n; m++)
          {
            float dx = pa[m][0] - pa[i][0], dy = pa[m][1] - pa[i][1];
            float tx = pb[i][0] + cs * dx - sn * dy, ty = pb[i][1] + sn * dx + cs * dy;
            float ex = tx - pb[m][0], ey = ty - pb[m][1];
            if (used[gj[m]] || ex * ex + ey * ey > MATCH_TOL * MATCH_TOL)
              continue;
            if (fabsf (wrap180 (pb[m][2] - pa[m][2] - rot)) > ANGLE_TOL)
              continue;
            used[gj[m]] = 1;
            inl++;
          }
        if (inl > best)
          best = inl;
      }

  free (pa);
  free (pb);
  free (gj);
  free (used);
  return best;
}
