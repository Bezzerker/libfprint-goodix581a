/*
 * Minimal SIFT keypoint extraction and geometric matching for small
 * fingerprint images (no external dependencies).
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#pragma once

#include <stdint.h>

#define SIGM_DESC_LEN 128

typedef struct
{
  float   x, y;
  float   angle; /* degrees */
  uint8_t desc[SIGM_DESC_LEN];
} SigmKeypoint;

typedef struct
{
  int           n;
  SigmKeypoint *kp;
} SigmFeatures;

/* Extract features from an 8-bit grayscale image. Coordinates are in the
 * pixel units of the input image. Free with sigm_features_free(). */
SigmFeatures *sigm_extract (const uint8_t *img, int width, int height, int max_keypoints);

void          sigm_features_free (SigmFeatures *f);

/* Number of matches consistent with one rigid transform (rotation +
 * translation, scale within 15%). Higher is better. If @candidates is not
 * NULL it receives the number of descriptor matches that were considered. */
int           sigm_match (const SigmFeatures *probe, const SigmFeatures *gallery,
                          int *candidates);
