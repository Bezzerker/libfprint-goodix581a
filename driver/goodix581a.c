/*
 * Goodix 27c6:581a (GM168SEC "Milan HV", Xiaomi Mi Notebook Pro 15.6 2021)
 *
 * Match-on-host sensor behind an MCU. Commands use the Goodix 0xa0 message
 * protocol; images arrive over a TLS-PSK session in which the MCU is the
 * client. The PSK is installed by this driver (white-box blob, same method as
 * the Windows driver's PresetPskWriteKey) when the MCU holds a different one.
 *
 * The 64x80 (~500 dpi) window is too small for NBIS minutiae matching, so
 * matching is done here: SIFT keypoints + rigid-transform consensus
 * (sigmatch.c), templates stored as raw print data.
 *
 * Protocol and config recovered from the Windows driver (Wbdi.dll 3.0.81.320)
 * and goodix-fp-dump (driver_52xd.py).
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#define FP_COMPONENT "goodix581a"

#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "drivers_api.h"
#include "sigmatch.h"

#define EP_OUT 0x01
#define EP_IN 0x83
#define TIMEOUT_MS 2000
#define DRAIN_TIMEOUT_MS 100

#define SENSOR_W 64   /* MCU streams 80 lines of 64 pixels */
#define SENSOR_H 80
#define N_PIXELS (SENSOR_W * SENSOR_H)
#define RAW_LEN (N_PIXELS * 3 / 2)
#define MAX_KEYPOINTS 150
#define MIN_KEYPOINTS 25
/* score = sum over enrolled samples of (rigid-consensus inliers - 3), clipped
 * at 0, so one lucky sample cannot pass alone. Measured on 56 different-finger
 * attempts: max 4; the same finger reaches >= 10 in about 55% of attempts. */
#define MATCH_INLIER_FLOOR 3
#define MATCH_THRESHOLD 10
#define TEMPLATE_VERSION 1

#define POLL_MS 50
/* max per-channel change of the 8 FDT levels: <= 2 when empty, 90..120 with a
 * finger. Image-based detection is unusable: lifted fingers leave a latent print. */
#define FDT_CHANNELS 8
#define FDT_ON_DELTA 40
#define FDT_OFF_DELTA 15
#define FDT_DEBOUNCE 2
/* a baseline older than this is retaken on open: temperature drifts while idle */
#define FDT_BASE_MAX_AGE (60 * G_USEC_PER_SEC)

#define FLAGS_MSG 0xa0
#define FLAGS_TLS 0xb0
#define FLAGS_TLS_DATA 0xb2

#define CMD_NOP 0x00
#define CMD_GET_IMAGE 0x20
#define CMD_FDT_MODE 0x36
#define CMD_WRITE_REG 0x80
#define CMD_UPLOAD_CONFIG 0x90
#define CMD_RESET 0xa2
#define CMD_FW_VERSION 0xa8
#define CMD_ACK 0xb0
#define CMD_SET_DRV_STATE 0xc4
#define CMD_REQUEST_TLS 0xd0
#define CMD_PSK_WRITE 0xe0
#define CMD_PSK_READ 0xe4

#define FW_PREFIX "GFUSB_GM168SEC_APP_"

static const guint8 psk[32] = { 0 };

/* the all-zero PSK encrypted with the MCU white-box key, from goodix-fp-dump
 * (MIT License, Copyright (c) 2022 Goodix Fingerprint Linux Development; see NOTICE) */
static const guint8 psk_white_box[] = {
  0xec, 0x35, 0xae, 0x3a, 0xbb, 0x45, 0xed, 0x3f, 0x12, 0xc4, 0x75, 0x1f,
  0x1e, 0x5c, 0x2c, 0xc0, 0x5b, 0x3c, 0x54, 0x52, 0xe9, 0x10, 0x4d, 0x9f,
  0x2a, 0x31, 0x18, 0x64, 0x4f, 0x37, 0xa0, 0x4b, 0x6f, 0xd6, 0x6b, 0x1d,
  0x97, 0xcf, 0x80, 0xf1, 0x34, 0x5f, 0x76, 0xc8, 0x4f, 0x03, 0xff, 0x30,
  0xbb, 0x51, 0xbf, 0x30, 0x8f, 0x2a, 0x98, 0x75, 0xc4, 0x1e, 0x65, 0x92,
  0xcd, 0x2a, 0x2f, 0x9e, 0x60, 0x80, 0x9b, 0x17, 0xb5, 0x31, 0x60, 0x37,
  0xb6, 0x9b, 0xb2, 0xfa, 0x5d, 0x4c, 0x8a, 0xc3, 0x1e, 0xdb, 0x33, 0x94,
  0x04, 0x6e, 0xc0, 0x6b, 0xbd, 0xac, 0xc5, 0x7d, 0xa6, 0xa7, 0x56, 0xc5,
};

/* SHA-256 based PMK hash the MCU reports for the all-zero PSK */
static const guint8 pmk_hash_zero[32] = {
  0x66, 0x68, 0x7a, 0xad, 0xf8, 0x62, 0xbd, 0x77, 0x6c, 0x8f, 0xc1, 0x8b,
  0x8e, 0x9f, 0x8e, 0x20, 0x08, 0x97, 0x14, 0x85, 0x6e, 0xe2, 0x33, 0xb3,
  0x90, 0x2a, 0x59, 0x1d, 0x0d, 0x5f, 0x29, 0x25,
};

/* Wbdi.dll config for this chip (file offset 0x2124c0) with the OTP-derived
 * TCODE (tag 0x5c) filled in and the checksum fixed. */
static const guint8 sensor_config[256] = {
  0x70, 0x11, 0x60, 0x71, 0x2c, 0x9d, 0x2c, 0xc9, 0x1c, 0xe5, 0x18, 0xfd,
  0x00, 0xfd, 0x00, 0xfd, 0x03, 0xba, 0x00, 0x01, 0x80, 0xca, 0x00, 0x08,
  0x00, 0x84, 0x00, 0xbe, 0xc3, 0x86, 0x00, 0xb1, 0xb6, 0x88, 0x00, 0xba,
  0xba, 0x8a, 0x00, 0xb3, 0xb3, 0x8c, 0x00, 0xbc, 0xbc, 0x8e, 0x00, 0xb1,
  0xb1, 0x90, 0x00, 0xbb, 0xbb, 0x92, 0x00, 0xb1, 0xb1, 0x94, 0x00, 0x00,
  0x00, 0x96, 0x00, 0x00, 0x00, 0x98, 0x00, 0x00, 0x00, 0x9a, 0x00, 0x00,
  0x00, 0xd2, 0x00, 0x00, 0x00, 0xd4, 0x00, 0x00, 0x00, 0xd6, 0x00, 0x00,
  0x00, 0xd8, 0x00, 0x00, 0x00, 0x50, 0x00, 0x01, 0x05, 0xd0, 0x00, 0x00,
  0x00, 0x70, 0x00, 0x00, 0x00, 0x72, 0x00, 0x78, 0x56, 0x74, 0x00, 0x34,
  0x12, 0x20, 0x00, 0x10, 0x40, 0x2a, 0x01, 0x02, 0x04, 0x22, 0x00, 0x01,
  0x20, 0x24, 0x00, 0x32, 0x00, 0x80, 0x00, 0x01, 0x00, 0x5c, 0x00, 0x01,
  0x01, 0x56, 0x00, 0x24, 0x20, 0x58, 0x00, 0x01, 0x02, 0x32, 0x00, 0x04,
  0x02, 0x66, 0x00, 0x00, 0x02, 0x7c, 0x00, 0x00, 0x58, 0x82, 0x00, 0x7f,
  0x08, 0x2a, 0x01, 0x82, 0x07, 0x22, 0x00, 0x01, 0x20, 0x24, 0x00, 0x14,
  0x00, 0x80, 0x00, 0x01, 0x40, 0x5c, 0x00, 0xea, 0x00, 0x56, 0x00, 0x06,
  0x14, 0x58, 0x00, 0x04, 0x02, 0x32, 0x00, 0x0c, 0x02, 0x66, 0x00, 0x00,
  0x02, 0x7c, 0x00, 0x00, 0x58, 0x82, 0x00, 0x7f, 0x08, 0x2a, 0x01, 0x08,
  0x00, 0x5c, 0x00, 0x01, 0x01, 0x54, 0x00, 0x00, 0x01, 0x62, 0x00, 0x08,
  0x04, 0x64, 0x00, 0x10, 0x00, 0x66, 0x00, 0x00, 0x02, 0x7c, 0x00, 0x00,
  0x58, 0x2a, 0x01, 0x08, 0x00, 0x5c, 0x00, 0xe8, 0x00, 0x52, 0x00, 0x08,
  0x00, 0x54, 0x00, 0x00, 0x01, 0x66, 0x00, 0x00, 0x02, 0x7c, 0x00, 0x00,
  0x58, 0x20, 0xc5, 0x0f,
};

/* mode 0x0301 + 4 DAC values (0x127, 0x121, 0x127, 0x123) */
static const guint8 image_request[] = {
  0x01, 0x03, 0x27, 0x01, 0x21, 0x01, 0x27, 0x01, 0x23, 0x01,
};

typedef enum {
  RX_ACK,
  RX_REPLY,
  RX_PACK,
} RxMode;

struct _FpiDeviceGoodix581a
{
  FpDevice    parent;

  /* current exchange */
  guint8      cmd;
  gboolean    want_reply;
  guint8      pack_flags;
  RxMode      rx_mode;
  GByteArray *rx;
  GByteArray *reply;

  SSL_CTX    *ssl_ctx;
  SSL        *ssl;
  BIO        *ssl_in;
  BIO        *ssl_out;

  guint16     frame[N_PIXELS];
  guint16     background[N_PIXELS];
  guint16     fdt_base[FDT_CHANNELS];
  gboolean    have_fdt_base;
  gint64      fdt_base_time; /* wall clock, so time asleep counts */
  gboolean    capturing;

  GPtrArray  *enroll_samples; /* GVariant "ay" per sample */
  gboolean    finger_on;
  int         streak;
};

G_DECLARE_FINAL_TYPE (FpiDeviceGoodix581a, fpi_device_goodix581a, FPI,
                      DEVICE_GOODIX581A, FpDevice);
G_DEFINE_TYPE (FpiDeviceGoodix581a, fpi_device_goodix581a, FP_TYPE_DEVICE);

static GError *
proto_error (const char *msg)
{
  return fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "%s", msg);
}

/* ---- Goodix message framing ---------------------------------------------- */

static GByteArray *
build_pack (guint8 flags, const guint8 *payload, gsize len)
{
  GByteArray *out = g_byte_array_new ();
  guint8 hdr[4] = { flags, len & 0xff, len >> 8, 0 };

  hdr[3] = (hdr[0] + hdr[1] + hdr[2]) & 0xff;
  g_byte_array_append (out, hdr, 4);
  g_byte_array_append (out, payload, len);
  return out;
}

static GByteArray *
build_command (guint8 cmd, const guint8 *payload, gsize len)
{
  g_autoptr(GByteArray) msg = g_byte_array_new ();
  guint8 hdr[3] = { cmd, (len + 1) & 0xff, (len + 1) >> 8 };
  guint8 sum = 0;
  guint8 checksum;

  g_byte_array_append (msg, hdr, 3);
  g_byte_array_append (msg, payload, len);
  for (guint i = 0; i < msg->len; i++)
    sum += msg->data[i];
  /* NOP is the only command sent with the "no checksum" marker */
  checksum = cmd == CMD_NOP ? 0x88 : (guint8) (0xaa - sum);
  g_byte_array_append (msg, &checksum, 1);

  return build_pack (FLAGS_MSG, msg->data, msg->len);
}

/* ---- async exchange: write, then ack / reply / raw pack -------------------- */

static void rx_submit (FpiSsm *ssm, FpDevice *dev, guint timeout);

static void
rx_process (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceGoodix581a *self = FPI_DEVICE_GOODIX581A (dev);
  const guint8 *d;
  guint len;

  if (self->rx->len < 4)
    {
      rx_submit (ssm, dev, TIMEOUT_MS);
      return;
    }

  d = self->rx->data;
  if (((d[0] + d[1] + d[2]) & 0xff) != d[3])
    {
      fpi_ssm_mark_failed (ssm, proto_error ("Bad pack checksum"));
      return;
    }
  len = d[1] | d[2] << 8;
  if (self->rx->len < 4 + len)
    {
      rx_submit (ssm, dev, TIMEOUT_MS);
      return;
    }

  if (self->rx_mode == RX_PACK)
    {
      if (d[0] != self->pack_flags)
        {
          fpi_ssm_mark_failed (ssm, proto_error ("Unexpected pack type"));
          return;
        }
      g_byte_array_set_size (self->reply, 0);
      g_byte_array_append (self->reply, d + 4, len);
      g_byte_array_set_size (self->rx, 0);
      fpi_ssm_next_state (ssm);
      return;
    }

  /* message protocol: cmd, u16 length (incl. checksum), payload, checksum */
  if (d[0] != FLAGS_MSG || len < 4)
    {
      fpi_ssm_mark_failed (ssm, proto_error ("Unexpected message"));
      return;
    }

  if (self->rx_mode == RX_ACK)
    {
      if (d[4] != CMD_ACK || d[7] != self->cmd || !(d[8] & 0x1))
        {
          fp_warn ("Bad ack for command 0x%02x", self->cmd);
          fpi_ssm_mark_failed (ssm, proto_error ("Command not acknowledged"));
          return;
        }
      g_byte_array_remove_range (self->rx, 0, 4 + len);
      if (self->want_reply)
        {
          self->rx_mode = RX_REPLY;
          if (self->rx->len > 0)
            rx_process (ssm, dev);
          else
            rx_submit (ssm, dev, TIMEOUT_MS);
        }
      else
        {
          fpi_ssm_next_state (ssm);
        }
      return;
    }

  if (d[4] != self->cmd)
    {
      fpi_ssm_mark_failed (ssm, proto_error ("Reply to wrong command"));
      return;
    }
  g_byte_array_set_size (self->reply, 0);
  g_byte_array_append (self->reply, d + 7, (d[5] | d[6] << 8) - 1);
  g_byte_array_set_size (self->rx, 0);
  fpi_ssm_next_state (ssm);
}

static void
rx_cb (FpiUsbTransfer *transfer, FpDevice *dev, gpointer user_data, GError *error)
{
  FpiDeviceGoodix581a *self = FPI_DEVICE_GOODIX581A (dev);

  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }
  g_byte_array_append (self->rx, transfer->buffer, transfer->actual_length);
  rx_process (transfer->ssm, dev);
}

static void
rx_submit (FpiSsm *ssm, FpDevice *dev, guint timeout)
{
  FpiUsbTransfer *transfer = fpi_usb_transfer_new (dev);

  fpi_usb_transfer_fill_bulk (transfer, EP_IN, 0x2000);
  transfer->ssm = ssm;
  fpi_usb_transfer_submit (transfer, timeout, NULL, rx_cb, NULL);
}

static void
tx_cb (FpiUsbTransfer *transfer, FpDevice *dev, gpointer user_data, GError *error)
{
  FpiDeviceGoodix581a *self = FPI_DEVICE_GOODIX581A (dev);

  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }
  if (GPOINTER_TO_INT (user_data))
    {
      g_byte_array_set_size (self->rx, 0);
      self->rx_mode = RX_ACK;
      rx_submit (transfer->ssm, dev, TIMEOUT_MS);
    }
  else
    {
      fpi_ssm_next_state (transfer->ssm);
    }
}

static void
tx_submit (FpiSsm *ssm, FpDevice *dev, GByteArray *pack, gboolean expect_ack)
{
  FpiUsbTransfer *transfer = fpi_usb_transfer_new (dev);
  gsize padded = (pack->len + 63) / 64 * 64;
  guint8 *buf = g_malloc0 (padded);

  memcpy (buf, pack->data, pack->len);
  fpi_usb_transfer_fill_bulk_full (transfer, EP_OUT, buf, padded, g_free);
  transfer->ssm = ssm;
  transfer->short_is_error = TRUE;
  fpi_usb_transfer_submit (transfer, TIMEOUT_MS, NULL, tx_cb, GINT_TO_POINTER (expect_ack));
  g_byte_array_unref (pack);
}

/* send a command; advances the SSM after the ack (and reply, if wanted) */
static void
send_cmd (FpiSsm *ssm, FpDevice *dev, guint8 cmd, const guint8 *payload, gsize len,
          gboolean want_reply)
{
  FpiDeviceGoodix581a *self = FPI_DEVICE_GOODIX581A (dev);

  self->cmd = cmd;
  self->want_reply = want_reply;
  tx_submit (ssm, dev, build_command (cmd, payload, len), TRUE);
}

static void
read_pack (FpiSsm *ssm, FpDevice *dev, guint8 flags)
{
  FpiDeviceGoodix581a *self = FPI_DEVICE_GOODIX581A (dev);

  self->rx_mode = RX_PACK;
  self->pack_flags = flags;
  g_byte_array_set_size (self->rx, 0);
  rx_submit (ssm, dev, TIMEOUT_MS);
}

/* ---- TLS (we are the server, the MCU is the client) ---------------------- */

static unsigned int
psk_server_cb (SSL *ssl, const char *identity, unsigned char *out, unsigned int max_len)
{
  if (max_len < sizeof (psk))
    return 0;
  memcpy (out, psk, sizeof (psk));
  return sizeof (psk);
}

static void
tls_free (FpiDeviceGoodix581a *self)
{
  g_clear_pointer (&self->ssl, SSL_free); /* frees both BIOs */
  self->ssl_in = self->ssl_out = NULL;
  g_clear_pointer (&self->ssl_ctx, SSL_CTX_free);
}

static GError *
tls_init (FpiDeviceGoodix581a *self)
{
  tls_free (self);
  self->ssl_ctx = SSL_CTX_new (TLS_server_method ());
  if (!self->ssl_ctx)
    return proto_error ("SSL_CTX_new failed");
  SSL_CTX_set_min_proto_version (self->ssl_ctx, TLS1_2_VERSION);
  SSL_CTX_set_max_proto_version (self->ssl_ctx, TLS1_2_VERSION);
  SSL_CTX_set_cipher_list (self->ssl_ctx, "PSK-AES128-CBC-SHA256:@SECLEVEL=0");
  SSL_CTX_set_psk_server_callback (self->ssl_ctx, psk_server_cb);

  self->ssl = SSL_new (self->ssl_ctx);
  self->ssl_in = BIO_new (BIO_s_mem ());
  self->ssl_out = BIO_new (BIO_s_mem ());
  SSL_set_bio (self->ssl, self->ssl_in, self->ssl_out);
  SSL_set_accept_state (self->ssl);
  return NULL;
}

/* feed a handshake record from the MCU; returns what we must send back */
static GByteArray *
tls_feed (FpiDeviceGoodix581a *self, GByteArray *in, GError **error)
{
  GByteArray *out = g_byte_array_new ();
  guint8 buf[4096];
  int n, r;

  BIO_write (self->ssl_in, in->data, in->len);
  r = SSL_do_handshake (self->ssl);
  if (r <= 0 && SSL_get_error (self->ssl, r) != SSL_ERROR_WANT_READ)
    {
      fp_warn ("TLS handshake failed: %s", ERR_error_string (ERR_get_error (), NULL));
      *error = proto_error ("TLS handshake failed");
    }
  while ((n = BIO_read (self->ssl_out, buf, sizeof (buf))) > 0)
    g_byte_array_append (out, buf, n);
  return out;
}

/* ---- open: firmware/PSK check, reset, TLS, config ------------------------- */

enum open_states {
  OPEN_NOP,
  OPEN_DRAIN,
  OPEN_FW_VERSION,
  OPEN_FW_CHECK,
  OPEN_PSK_READ,
  OPEN_PSK_CHECK,
  OPEN_PSK_WRITE,
  OPEN_PSK_WRITE_CHECK,
  OPEN_RESET,
  OPEN_RESET_CHECK,
  OPEN_TLS_REQUEST,
  OPEN_TLS_HELLO,
  OPEN_TLS_SERVER_HELLO,
  OPEN_TLS_CLIENT_1,
  OPEN_TLS_CLIENT_2,
  OPEN_TLS_CLIENT_3,
  OPEN_TLS_FINISHED,
  OPEN_CONFIG,
  OPEN_CONFIG_CHECK,
  OPEN_DRV_STATE,
  OPEN_NUM_STATES,
};

static void
drain_cb (FpiUsbTransfer *transfer, FpDevice *dev, gpointer user_data, GError *error)
{
  if (error)
    {
      /* a timeout means the IN pipe is empty */
      if (g_error_matches (error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_TIMED_OUT))
        fpi_ssm_next_state (transfer->ssm);
      else
        fpi_ssm_mark_failed (transfer->ssm, error);
      g_clear_error (&error);
      return;
    }
  fpi_ssm_jump_to_state (transfer->ssm, OPEN_DRAIN);
}

static void
open_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceGoodix581a *self = FPI_DEVICE_GOODIX581A (dev);
  GError *error = NULL;
  GByteArray *out;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case OPEN_NOP:
      {
        static const guint8 zero[4] = { 0 };
        tx_submit (ssm, dev, build_command (CMD_NOP, zero, 4), FALSE);
        break;
      }

    case OPEN_DRAIN:
      {
        FpiUsbTransfer *transfer = fpi_usb_transfer_new (dev);
        fpi_usb_transfer_fill_bulk (transfer, EP_IN, 0x2000);
        transfer->ssm = ssm;
        fpi_usb_transfer_submit (transfer, DRAIN_TIMEOUT_MS, NULL, drain_cb, NULL);
        break;
      }

    case OPEN_FW_VERSION:
      send_cmd (ssm, dev, CMD_FW_VERSION, (const guint8 *) "\0\0", 2, TRUE);
      break;

    case OPEN_FW_CHECK:
      {
        g_autofree char *fw = g_strndup ((char *) self->reply->data, self->reply->len);
        fp_info ("Firmware: %s", fw);
        if (!g_str_has_prefix (fw, FW_PREFIX))
          {
            fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED,
                                                                "Unsupported firmware %s", fw));
            return;
          }
        fpi_ssm_next_state (ssm);
        break;
      }

    case OPEN_PSK_READ:
      {
        guint32 req[4] = { GUINT32_TO_LE (32), 0, GUINT32_TO_LE (0xbb020001), 0 };
        send_cmd (ssm, dev, CMD_PSK_READ, (guint8 *) req, sizeof (req), TRUE);
        break;
      }

    case OPEN_PSK_CHECK:
      if (self->reply->len >= 9 + 32 && self->reply->data[0] == 0 &&
          memcmp (self->reply->data + 9, pmk_hash_zero, 32) == 0)
        {
          fpi_ssm_jump_to_state (ssm, OPEN_RESET);
          return;
        }
      fp_info ("MCU holds a foreign PSK, installing ours");
      fpi_ssm_next_state (ssm);
      break;

    case OPEN_PSK_WRITE:
      {
        /* u32 total, u32 chunk len, u32 offset, then pre-flags, flags, len, blob */
        static const guint8 pre[] = { 0x56, 0xa5, 0xbb, 0x95, 0x6b, 0x7c, 0x8d, 0x9e, 0x00, 0x00 };
        g_autoptr(GByteArray) body = g_byte_array_new ();
        g_autoptr(GByteArray) msg = g_byte_array_new ();
        guint32 v;

        g_byte_array_append (body, pre, sizeof (pre));
        v = GUINT32_TO_LE (0xbb010003);
        g_byte_array_append (body, (guint8 *) &v, 4);
        v = GUINT32_TO_LE (sizeof (psk_white_box));
        g_byte_array_append (body, (guint8 *) &v, 4);
        g_byte_array_append (body, psk_white_box, sizeof (psk_white_box));

        v = GUINT32_TO_LE (body->len);
        g_byte_array_append (msg, (guint8 *) &v, 4);
        g_byte_array_append (msg, (guint8 *) &v, 4);
        v = 0;
        g_byte_array_append (msg, (guint8 *) &v, 4);
        g_byte_array_append (msg, body->data, body->len);
        send_cmd (ssm, dev, CMD_PSK_WRITE, msg->data, msg->len, TRUE);
        break;
      }

    case OPEN_PSK_WRITE_CHECK:
      if (self->reply->len < 1 || self->reply->data[0] != 0)
        {
          fpi_ssm_mark_failed (ssm, proto_error ("PSK write rejected"));
          return;
        }
      fpi_ssm_next_state (ssm);
      break;

    case OPEN_RESET:
      send_cmd (ssm, dev, CMD_RESET, (const guint8 *) "\x05\x14", 2, TRUE);
      break;

    case OPEN_RESET_CHECK:
      if (self->reply->len < 1 || self->reply->data[0] != 1)
        {
          fpi_ssm_mark_failed (ssm, proto_error ("Sensor reset failed"));
          return;
        }
      if ((error = tls_init (self)))
        {
          fpi_ssm_mark_failed (ssm, error);
          return;
        }
      fpi_ssm_next_state (ssm);
      break;

    case OPEN_TLS_REQUEST:
      send_cmd (ssm, dev, CMD_REQUEST_TLS, (const guint8 *) "\0\0", 2, FALSE);
      break;

    case OPEN_TLS_CLIENT_2:
    case OPEN_TLS_CLIENT_3:
      /* key exchange / change cipher spec need no answer: just buffer them */
      BIO_write (self->ssl_in, self->reply->data, self->reply->len);
      /* fallthrough */
    case OPEN_TLS_HELLO:
    case OPEN_TLS_CLIENT_1:
      read_pack (ssm, dev, FLAGS_TLS);
      break;

    case OPEN_TLS_SERVER_HELLO:
    case OPEN_TLS_FINISHED:
      /* reply holds the last client record; earlier ones were fed already */
      out = tls_feed (self, self->reply, &error);
      if (error)
        {
          g_byte_array_unref (out);
          fpi_ssm_mark_failed (ssm, error);
          return;
        }
      if (fpi_ssm_get_cur_state (ssm) == OPEN_TLS_FINISHED && !SSL_is_init_finished (self->ssl))
        {
          g_byte_array_unref (out);
          fpi_ssm_mark_failed (ssm, proto_error ("TLS handshake incomplete"));
          return;
        }
      tx_submit (ssm, dev, build_pack (FLAGS_TLS, out->data, out->len), FALSE);
      g_byte_array_unref (out);
      break;

    case OPEN_CONFIG:
      send_cmd (ssm, dev, CMD_UPLOAD_CONFIG, sensor_config, sizeof (sensor_config), TRUE);
      break;

    case OPEN_CONFIG_CHECK:
      if (self->reply->len < 1 || self->reply->data[0] != 1)
        {
          fpi_ssm_mark_failed (ssm, proto_error ("Sensor config rejected"));
          return;
        }
      fpi_ssm_next_state (ssm);
      break;

    case OPEN_DRV_STATE:
      send_cmd (ssm, dev, CMD_SET_DRV_STATE, (const guint8 *) "\x01\x00", 2, FALSE);
      break;
    }
}

static void
open_complete (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceGoodix581a *self = FPI_DEVICE_GOODIX581A (dev);

  if (error)
    tls_free (self);
  /* the FDT/background baselines are kept across close/open: fprintd reopens
   * the device for every attempt, often while the finger is still on the
   * sensor. They survive the sensor reset (FDT +-1, frame +-22 measured). */
  if (g_get_real_time () - self->fdt_base_time > FDT_BASE_MAX_AGE)
    self->have_fdt_base = FALSE;
  self->streak = 0;
  fpi_device_open_complete (dev, error);
}

static void
dev_open (FpDevice *dev)
{
  GError *error = NULL;

  if (!g_usb_device_claim_interface (fpi_device_get_usb_device (dev), 0, 0, &error))
    {
      fpi_device_open_complete (dev, error);
      return;
    }
  fpi_ssm_start (fpi_ssm_new (dev, open_run_state, OPEN_NUM_STATES), open_complete);
}

static void
dev_close (FpDevice *dev)
{
  GError *error = NULL;

  tls_free (FPI_DEVICE_GOODIX581A (dev));
  g_usb_device_release_interface (fpi_device_get_usb_device (dev), 0, 0, &error);
  fpi_device_close_complete (dev, error);
}

/* ---- one frame ------------------------------------------------------------ */

enum frame_states {
  FRAME_REG_ON,
  FRAME_REQUEST,
  FRAME_READ,
  FRAME_DECODE,
  FRAME_REG_OFF,
  FRAME_NUM_STATES,
};

static GError *
decode_frame (FpiDeviceGoodix581a *self)
{
  guint8 raw[RAW_LEN + 4];
  gsize have = 0;
  int n;

  /* pack payload: 9 bytes of MCU header, then TLS application records */
  if (self->reply->len <= 9)
    return proto_error ("Short image pack");
  BIO_write (self->ssl_in, self->reply->data + 9, self->reply->len - 9);
  while (have < sizeof (raw) && (n = SSL_read (self->ssl, raw + have, sizeof (raw) - have)) > 0)
    have += n;
  if (have != sizeof (raw))
    return proto_error ("Short image payload");

  /* 12-bit pixels, 4 per 6 bytes; trailing 4 bytes are a checksum */
  for (gsize i = 0, p = 0; i < RAW_LEN; i += 6, p += 4)
    {
      const guint8 *c = raw + i;
      self->frame[p] = ((c[0] & 0xf) << 8) | c[1];
      self->frame[p + 1] = (c[3] << 4) | (c[0] >> 4);
      self->frame[p + 2] = ((c[5] & 0xf) << 8) | c[2];
      self->frame[p + 3] = (c[4] << 4) | (c[5] >> 4);
    }
  return NULL;
}

static void
frame_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceGoodix581a *self = FPI_DEVICE_GOODIX581A (dev);
  GError *error;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case FRAME_REG_ON:
      /* register 0x022c = 0x030a around the capture, as the Windows driver does */
      send_cmd (ssm, dev, CMD_WRITE_REG, (const guint8 *) "\x00\x2c\x02\x0a\x03", 5, FALSE);
      break;

    case FRAME_REQUEST:
      send_cmd (ssm, dev, CMD_GET_IMAGE, image_request, sizeof (image_request), FALSE);
      break;

    case FRAME_READ:
      read_pack (ssm, dev, FLAGS_TLS_DATA);
      break;

    case FRAME_DECODE:
      if ((error = decode_frame (self)))
        fpi_ssm_mark_failed (ssm, error);
      else
        fpi_ssm_next_state (ssm);
      break;

    case FRAME_REG_OFF:
      send_cmd (ssm, dev, CMD_WRITE_REG, (const guint8 *) "\x00\x2c\x02\x0a\x02", 5, FALSE);
      break;
    }
}

/* ---- capture: wait for lift (if needed), wait for touch, grab one frame ---- */

enum capture_states {
  CAP_CHECK_CANCEL,
  CAP_FDT_ARM,
  CAP_FDT_READ,
  CAP_FDT_EVALUATE,
  CAP_FRAME,
  CAP_FRAME_EVALUATE,
  CAP_NUM_STATES,
};

/* FDT mode 0x010d with the image DACs; the last byte asks for a reply */
static const guint8 fdt_query[27] = {
  0x0d, 0x01, 0x27, 0x01, 0x21, 0x01, 0x27, 0x01, 0x23, 0x01,
};

static void
set_finger (FpiDeviceGoodix581a *self, gboolean on)
{
  self->finger_on = on;
  if (on)
    fpi_device_report_finger_status_changes (FP_DEVICE (self), FP_FINGER_STATUS_PRESENT,
                                             FP_FINGER_STATUS_NEEDED);
  else
    fpi_device_report_finger_status_changes (FP_DEVICE (self), FP_FINGER_STATUS_NONE,
                                             FP_FINGER_STATUS_PRESENT);
}

static void
evaluate_fdt (FpiSsm *ssm, FpiDeviceGoodix581a *self)
{
  guint16 levels[FDT_CHANNELS];
  int delta = 0;

  if (self->reply->len < 4 + sizeof (levels))
    {
      fpi_ssm_mark_failed (ssm, proto_error ("Short FDT reply"));
      return;
    }
  for (int i = 0; i < FDT_CHANNELS; i++)
    levels[i] = self->reply->data[4 + 2 * i] | self->reply->data[5 + 2 * i] << 8;

  if (!self->have_fdt_base)
    {
      /* sensor is assumed empty on the first open: take both baselines.
       * They persist across actions and reopens so a finger still resting on
       * the sensor when the next one starts is seen as present, not as background. */
      memcpy (self->fdt_base, levels, sizeof (levels));
      self->fdt_base_time = g_get_real_time ();
      self->have_fdt_base = TRUE;
      self->finger_on = FALSE;
      fpi_ssm_jump_to_state (ssm, CAP_FRAME);
      return;
    }

  for (int i = 0; i < FDT_CHANNELS; i++)
    delta = MAX (delta, ABS (levels[i] - self->fdt_base[i]));

  if (!self->finger_on)
    {
      self->streak = delta >= FDT_ON_DELTA ? self->streak + 1 : 0;
      if (delta < FDT_OFF_DELTA)
        {
          /* follow slow drift while the sensor is empty */
          memcpy (self->fdt_base, levels, sizeof (levels));
          self->fdt_base_time = g_get_real_time ();
        }
      if (self->streak >= FDT_DEBOUNCE)
        {
          self->streak = 0;
          set_finger (self, TRUE);
          self->capturing = TRUE;
          fpi_ssm_jump_to_state (ssm, CAP_FRAME);
          return;
        }
    }
  else
    {
      self->streak = delta < FDT_OFF_DELTA ? self->streak + 1 : 0;
      if (self->streak >= FDT_DEBOUNCE)
        {
          self->streak = 0;
          set_finger (self, FALSE);
          fpi_device_report_finger_status_changes (FP_DEVICE (self), FP_FINGER_STATUS_NEEDED,
                                                   FP_FINGER_STATUS_NONE);
          /* refresh the empty-sensor frame */
          fpi_ssm_jump_to_state (ssm, CAP_FRAME);
          return;
        }
    }

  fpi_ssm_jump_to_state_delayed (ssm, CAP_CHECK_CANCEL, POLL_MS);
}

static void
capture_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceGoodix581a *self = FPI_DEVICE_GOODIX581A (dev);
  guint8 query[sizeof (fdt_query)];

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case CAP_CHECK_CANCEL:
      if (g_cancellable_is_cancelled (fpi_device_get_cancellable (dev)))
        fpi_ssm_mark_failed (ssm, g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                                       "Cancelled"));
      else
        fpi_ssm_next_state (ssm);
      break;

    case CAP_FDT_ARM:
    case CAP_FDT_READ:
      memcpy (query, fdt_query, sizeof (query));
      query[sizeof (query) - 1] = fpi_ssm_get_cur_state (ssm) == CAP_FDT_READ;
      send_cmd (ssm, dev, CMD_FDT_MODE, query, sizeof (query), query[sizeof (query) - 1]);
      break;

    case CAP_FDT_EVALUATE:
      evaluate_fdt (ssm, self);
      break;

    case CAP_FRAME:
      fpi_ssm_start_subsm (ssm, fpi_ssm_new (dev, frame_run_state, FRAME_NUM_STATES));
      break;

    case CAP_FRAME_EVALUATE:
      if (self->capturing)
        {
          self->capturing = FALSE;
          fpi_ssm_mark_completed (ssm);
          return;
        }
      memcpy (self->background, self->frame, sizeof (self->frame));
      fpi_ssm_jump_to_state_delayed (ssm, CAP_CHECK_CANCEL, POLL_MS);
      break;
    }
}

static void
start_capture (FpiDeviceGoodix581a *self, FpiSsmCompletedCallback done)
{
  if (!self->finger_on)
    fpi_device_report_finger_status_changes (FP_DEVICE (self), FP_FINGER_STATUS_NEEDED,
                                             FP_FINGER_STATUS_NONE);
  fpi_ssm_start (fpi_ssm_new (FP_DEVICE (self), capture_run_state, CAP_NUM_STATES), done);
}

/* ---- features ------------------------------------------------------------- */

static int
cmp_int (gconstpointer a, gconstpointer b)
{
  return *(const int *) a - *(const int *) b;
}

/* frame - background, 1st..99th percentile stretched to 8 bit */
static SigmFeatures *
extract_features (FpiDeviceGoodix581a *self)
{
  int diff[N_PIXELS], sorted[N_PIXELS], lo, hi;
  guint8 img[N_PIXELS];

  for (int i = 0; i < N_PIXELS; i++)
    diff[i] = sorted[i] = self->frame[i] - self->background[i];
#ifdef GOODIX581A_DUMP
  /* test builds only: save int16 frame-background as $GOODIX581A_DUMP/NNN.raw */
  if (g_getenv ("GOODIX581A_DUMP"))
    {
      static int seq;
      gint16 raw[N_PIXELS];
      g_autofree char *path = g_strdup_printf ("%s/%03d.raw", g_getenv ("GOODIX581A_DUMP"), seq++);
      for (int i = 0; i < N_PIXELS; i++)
        raw[i] = diff[i];
      g_file_set_contents (path, (const char *) raw, sizeof (raw), NULL);
    }
#endif
  qsort (sorted, N_PIXELS, sizeof (int), cmp_int);
  lo = sorted[N_PIXELS / 100];
  hi = sorted[N_PIXELS - 1 - N_PIXELS / 100];
  if (hi <= lo)
    hi = lo + 1;
  for (int i = 0; i < N_PIXELS; i++)
    img[i] = CLAMP ((diff[i] - lo) * 255 / (hi - lo), 0, 255);

  return sigm_extract (img, SENSOR_W, SENSOR_H, MAX_KEYPOINTS);
}

/* template blob per sample: n x (float x, float y, float angle, 128 x u8) */
#define KP_BLOB_LEN (3 * sizeof (float) + SIGM_DESC_LEN)

static GVariant *
features_to_variant (SigmFeatures *f)
{
  g_autofree guint8 *blob = g_malloc (KP_BLOB_LEN * f->n);

  for (int i = 0; i < f->n; i++)
    {
      guint8 *p = blob + i * KP_BLOB_LEN;
      memcpy (p, &f->kp[i].x, sizeof (float));
      memcpy (p + 4, &f->kp[i].y, sizeof (float));
      memcpy (p + 8, &f->kp[i].angle, sizeof (float));
      memcpy (p + 12, f->kp[i].desc, SIGM_DESC_LEN);
    }
  return g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, blob, KP_BLOB_LEN * f->n, 1);
}

static SigmFeatures *
features_from_variant (GVariant *v)
{
  gsize len;
  const guint8 *blob = g_variant_get_fixed_array (v, &len, 1);
  SigmFeatures *f = calloc (1, sizeof (*f));

  f->n = len / KP_BLOB_LEN;
  f->kp = calloc (MAX (f->n, 1), sizeof (SigmKeypoint));
  for (int i = 0; i < f->n; i++)
    {
      const guint8 *p = blob + i * KP_BLOB_LEN;
      memcpy (&f->kp[i].x, p, sizeof (float));
      memcpy (&f->kp[i].y, p + 4, sizeof (float));
      memcpy (&f->kp[i].angle, p + 8, sizeof (float));
      memcpy (f->kp[i].desc, p + 12, SIGM_DESC_LEN);
    }
  return f;
}

/* sum of sigm_match inliers above MATCH_INLIER_FLOOR over all samples of a print */
static int
score_print (SigmFeatures *probe, FpPrint *print)
{
  g_autoptr(GVariant) data = NULL;
  g_autoptr(GVariant) samples = NULL;
  GVariantIter iter;
  GVariant *child;
  guint32 version;
  int score = 0;

  g_object_get (print, "fpi-data", &data, NULL);
  if (!data || !g_variant_is_of_type (data, G_VARIANT_TYPE ("(uaay)")))
    return 0;
  g_variant_get (data, "(u@aay)", &version, &samples);
  if (version != TEMPLATE_VERSION)
    return 0;

  g_variant_iter_init (&iter, samples);
  while ((child = g_variant_iter_next_value (&iter)))
    {
      SigmFeatures *f = features_from_variant (child);
      score += MAX (0, sigm_match (probe, f, NULL) - MATCH_INLIER_FLOOR);
      sigm_features_free (f);
      g_variant_unref (child);
    }
  return score;
}

/* ---- enroll ----------------------------------------------------------------- */

static void
enroll_capture_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceGoodix581a *self = FPI_DEVICE_GOODIX581A (dev);
  SigmFeatures *f;
  FpPrint *print = NULL;
  GVariantBuilder builder;

  if (error)
    {
      g_clear_pointer (&self->enroll_samples, g_ptr_array_unref);
      fpi_device_enroll_complete (dev, NULL, error);
      return;
    }

  f = extract_features (self);
  fp_dbg ("enroll sample: %d keypoints", f->n);
  if (f->n < MIN_KEYPOINTS)
    {
      sigm_features_free (f);
      fpi_device_enroll_progress (dev, self->enroll_samples->len, NULL,
                                  fpi_device_retry_new (FP_DEVICE_RETRY_CENTER_FINGER));
      start_capture (self, enroll_capture_done);
      return;
    }
  g_ptr_array_add (self->enroll_samples, g_variant_ref_sink (features_to_variant (f)));
  sigm_features_free (f);
  fpi_device_enroll_progress (dev, self->enroll_samples->len, NULL, NULL);

  if (self->enroll_samples->len < (guint) fp_device_get_nr_enroll_stages (dev))
    {
      start_capture (self, enroll_capture_done);
      return;
    }

  g_variant_builder_init (&builder, G_VARIANT_TYPE ("aay"));
  for (guint i = 0; i < self->enroll_samples->len; i++)
    g_variant_builder_add_value (&builder, g_ptr_array_index (self->enroll_samples, i));
  g_clear_pointer (&self->enroll_samples, g_ptr_array_unref);

  fpi_device_get_enroll_data (dev, &print);
  fpi_print_set_type (print, FPI_PRINT_RAW);
  g_object_set (print, "fpi-data",
                g_variant_new ("(u@aay)", TEMPLATE_VERSION, g_variant_builder_end (&builder)),
                NULL);
  fpi_device_enroll_complete (dev, g_object_ref (print), NULL);
}

static void
dev_enroll (FpDevice *dev)
{
  FpiDeviceGoodix581a *self = FPI_DEVICE_GOODIX581A (dev);

  self->enroll_samples = g_ptr_array_new_with_free_func ((GDestroyNotify) g_variant_unref);
  start_capture (self, enroll_capture_done);
}

/* ---- verify / identify ---------------------------------------------------- */

static void
match_capture_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceGoodix581a *self = FPI_DEVICE_GOODIX581A (dev);
  gboolean identify = fpi_device_get_current_action (dev) == FPI_DEVICE_ACTION_IDENTIFY;
  SigmFeatures *probe;

  if (error)
    {
      if (identify)
        fpi_device_identify_complete (dev, error);
      else
        fpi_device_verify_complete (dev, error);
      return;
    }

  probe = extract_features (self);
  if (probe->n < MIN_KEYPOINTS)
    {
      GError *retry = fpi_device_retry_new (FP_DEVICE_RETRY_CENTER_FINGER);
      fp_dbg ("probe has only %d keypoints", probe->n);
      sigm_features_free (probe);
      if (identify)
        {
          fpi_device_identify_report (dev, NULL, NULL, retry);
          fpi_device_identify_complete (dev, NULL);
        }
      else
        {
          fpi_device_verify_report (dev, FPI_MATCH_ERROR, NULL, retry);
          fpi_device_verify_complete (dev, NULL);
        }
      return;
    }

  if (identify)
    {
      GPtrArray *prints;
      FpPrint *match = NULL;
      int best = 0;

      fpi_device_get_identify_data (dev, &prints);
      for (guint i = 0; i < prints->len; i++)
        {
          int s = score_print (probe, g_ptr_array_index (prints, i));
          fp_info ("identify score %d (threshold %d) for print %u", s, MATCH_THRESHOLD, i);
          if (s >= MATCH_THRESHOLD && s > best)
            best = s, match = g_ptr_array_index (prints, i);
        }
      fpi_device_identify_report (dev, match, NULL, NULL);
      fpi_device_identify_complete (dev, NULL);
    }
  else
    {
      FpPrint *template;
      int s;

      fpi_device_get_verify_data (dev, &template);
      s = score_print (probe, template);
      fp_info ("verify score %d (threshold %d)", s, MATCH_THRESHOLD);
      fpi_device_verify_report (dev, s >= MATCH_THRESHOLD ? FPI_MATCH_SUCCESS : FPI_MATCH_FAIL,
                                NULL, NULL);
      fpi_device_verify_complete (dev, NULL);
    }
  sigm_features_free (probe);
}

static void
dev_match (FpDevice *dev)
{
  FpiDeviceGoodix581a *self = FPI_DEVICE_GOODIX581A (dev);

  start_capture (self, match_capture_done);
}

/* ---- GObject -------------------------------------------------------------- */

static const FpIdEntry id_table[] = {
  { .vid = 0x27c6, .pid = 0x581a, },
  { .vid = 0, .pid = 0, },
};

static void
fpi_device_goodix581a_init (FpiDeviceGoodix581a *self)
{
  self->rx = g_byte_array_new ();
  self->reply = g_byte_array_new ();
}

static void
fpi_device_goodix581a_finalize (GObject *object)
{
  FpiDeviceGoodix581a *self = FPI_DEVICE_GOODIX581A (object);

  tls_free (self);
  g_clear_pointer (&self->enroll_samples, g_ptr_array_unref);
  g_byte_array_unref (self->rx);
  g_byte_array_unref (self->reply);
  G_OBJECT_CLASS (fpi_device_goodix581a_parent_class)->finalize (object);
}

static void
fpi_device_goodix581a_class_init (FpiDeviceGoodix581aClass *klass)
{
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);

  G_OBJECT_CLASS (klass)->finalize = fpi_device_goodix581a_finalize;

  dev_class->id = FP_COMPONENT;
  dev_class->full_name = "Goodix 27c6:581a (GM168SEC)";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->id_table = id_table;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  /* 3.2 x 4 mm window: many samples are needed to cover the finger */
  dev_class->nr_enroll_stages = 20;
  /* the MCU idles in finger-detect mode like on Windows; no heat-up model */
  dev_class->temp_hot_seconds = -1;

  dev_class->open = dev_open;
  dev_class->close = dev_close;
  dev_class->enroll = dev_enroll;
  dev_class->verify = dev_match;
  dev_class->identify = dev_match;

  fpi_device_class_auto_initialize_features (dev_class);
}
