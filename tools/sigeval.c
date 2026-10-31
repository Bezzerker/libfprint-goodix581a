/* Offline evaluation of driver/sigmatch.c: sigeval MAXKP file.raw... prints the
 * sigm_match score matrix (row = probe, column = gallery). Each .raw is
 * int16 80x64 (frame - background) as written by collect.py. */
#include <stdio.h>
#include <stdlib.h>

#include "../driver/sigmatch.h"

#define W 64
#define H 80

static int
cmp_int (const void *a, const void *b)
{
  return *(const int *) a - *(const int *) b;
}

/* same 1..99 percentile stretch the driver uses */
static void
to8 (const short *raw, unsigned char *out)
{
  int s[W * H], lo, hi;

  for (int i = 0; i < W * H; i++)
    s[i] = raw[i];
  qsort (s, W * H, sizeof (int), cmp_int);
  lo = s[W * H / 100];
  hi = s[W * H - 1 - W * H / 100];
  if (hi <= lo)
    hi = lo + 1;
  for (int i = 0; i < W * H; i++)
    {
      int v = (raw[i] - lo) * 255 / (hi - lo);
      out[i] = v < 0 ? 0 : v > 255 ? 255 : v;
    }
}

int
main (int argc, char **argv)
{
  int maxkp = atoi (argv[1]), n = argc - 2;
  SigmFeatures **f = calloc (n, sizeof (*f));

  for (int i = 0; i < n; i++)
    {
      short raw[W * H];
      unsigned char img[W * H];
      FILE *fp = fopen (argv[i + 2], "rb");
      if (!fp || fread (raw, sizeof (raw), 1, fp) != 1)
        return 1;
      fclose (fp);
      to8 (raw, img);
      f[i] = sigm_extract (img, W, H, maxkp);
      fprintf (stderr, "%d ", f[i]->n);
    }
  fprintf (stderr, "keypoints\n");
  /* "inliers/candidates" per pair */
  for (int i = 0; i < n; i++)
    for (int j = 0; j < n; j++)
      {
        int c = 0, s = i == j ? 0 : sigm_match (f[i], f[j], &c);
        printf ("%d/%d%c", s, c, j == n - 1 ? '\n' : ' ');
      }
  return 0;
}
