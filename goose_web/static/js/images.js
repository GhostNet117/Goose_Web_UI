// Images shown to the model (spec 039). The original file is always uploaded unchanged into Web_Uploads; what goes
// into the message as an image block is a copy made here: at most INLINE_MAX_SIDE pixels on the longest side, JPEG
// (PNG when the image has transparent parts and the PNG stays small), at most about INLINE_TARGET characters of
// base64 - made smaller step by step (quality, then size) when needed. A small image that already fits is sent as
// it is. Why: some OpenAI-compatible endpoints refuse request bodies above about 5 MB, Goose sends the whole
// conversation again at every turn, and `goose serve` drops a WebSocket message above 16 MiB (measured with Goose 1.57).
// planInline() keeps all images of one message under MESSAGE_INLINE_BUDGET; the others go as file links only.
// decode/encode/readBase64 are injectable so the steps can be tested without a browser (tests/test_frontend_uploads.py).

export const INLINE_MAX_SIDE = 1600;
export const INLINE_TARGET = 1024 * 1024;               // base64 characters of one image (about 1 MB)
export const MESSAGE_INLINE_BUDGET = 10 * 1024 * 1024;  // base64 characters of all images in one message
export const JPEG_QUALITIES = [0.85, 0.75, 0.65, 0.55];
export const SHRINK = 0.75;                              // each further step: 3/4 of the size
export const MIN_SIDE = 320;                             // smaller than this is no use to the model: link only
const PASS_THROUGH = new Set(['image/png', 'image/jpeg', 'image/gif', 'image/webp']);
const MAY_HAVE_ALPHA = new Set(['image/png', 'image/webp', 'image/gif', 'image/avif', 'image/svg+xml', 'image/x-icon', 'image/vnd.microsoft.icon']);

export const b64len = (bytes) => Math.ceil(bytes / 3) * 4;

// Why an image goes as a link only (shown on the attachment in the message box).
export const NOTES = {
  undecodable: 'sent as a link only: this browser cannot read this image format (HEIC, TIFF, ...)',
  too_large: 'sent as a link only: even a small copy of this image is too large to show the model',
  budget: 'sent as a link only: the images in this message already use the 10 MB shown to the model',
};

// -> { data, mimeType, width, height, bytes, scaled } or { skip: 'undecodable' | 'too_large' }
export async function prepareInline(file, { decode = decodeImage, encode = encodeImage, readBase64 = fileBase64 } = {}) {
  let img;
  try { img = await decode(file); } catch { return { skip: 'undecodable' }; }
  if (!img || !(img.width > 0) || !(img.height > 0)) return { skip: 'undecodable' };
  try {
    const long = Math.max(img.width, img.height);
    if (PASS_THROUGH.has(file.type) && long <= INLINE_MAX_SIDE && b64len(file.size) <= INLINE_TARGET) {
      const data = await readBase64(file);
      return { data, mimeType: file.type, width: img.width, height: img.height, bytes: data.length, scaled: false };
    }
    let scale = Math.min(1, INLINE_MAX_SIDE / long);
    for (;;) {
      const w = Math.max(1, Math.round(img.width * scale)), h = Math.max(1, Math.round(img.height * scale));
      if (img.alpha) {
        const png = await encode(img, w, h, 'image/png');
        if (png && png.length <= INLINE_TARGET) return { data: png, mimeType: 'image/png', width: w, height: h, bytes: png.length, scaled: true };
      }
      for (const q of JPEG_QUALITIES) {
        const jpg = await encode(img, w, h, 'image/jpeg', q);
        if (jpg && jpg.length <= INLINE_TARGET) return { data: jpg, mimeType: 'image/jpeg', width: w, height: h, bytes: jpg.length, scaled: true, quality: q };
      }
      if (Math.max(w, h) * SHRINK < MIN_SIDE) return { skip: 'too_large' };
      scale *= SHRINK;
    }
  } finally {
    if (img && typeof img.close === 'function') { try { img.close(); } catch { /* already closed */ } }
  }
}

// Which attachments of one message carry their image inline: in order, while the total stays within the budget.
// items: [{ inline: { bytes } | null }] -> [true | false, ...]
export function planInline(items, budget = MESSAGE_INLINE_BUDGET) {
  let used = 0;
  return items.map((a) => {
    const n = a && a.inline && a.inline.bytes;
    if (!n) return false;
    if (used + n > budget) return false;
    used += n;
    return true;
  });
}

// ---------------------------------------------------------------- browser implementations
export async function decodeImage(file) {
  const bmp = await createImageBitmap(file);
  const img = { width: bmp.width, height: bmp.height, source: bmp, alpha: false, close: () => bmp.close() };
  if (MAY_HAVE_ALPHA.has(file.type)) img.alpha = hasAlpha(bmp);
  return img;
}

function canvas(w, h) {
  if (typeof OffscreenCanvas !== 'undefined') return new OffscreenCanvas(w, h);
  const c = document.createElement('canvas'); c.width = w; c.height = h; return c;
}

// Look at a small copy: any pixel that is not fully opaque means transparency.
function hasAlpha(bmp) {
  const w = Math.min(64, bmp.width), h = Math.min(64, bmp.height);
  const c = canvas(w, h); const g = c.getContext('2d');
  g.drawImage(bmp, 0, 0, w, h);
  const px = g.getImageData(0, 0, w, h).data;
  for (let i = 3; i < px.length; i += 4) if (px[i] < 255) return true;
  return false;
}

async function blobOf(c, type, quality) {
  if (c.convertToBlob) return c.convertToBlob({ type, quality });
  return new Promise((resolve, reject) => c.toBlob((b) => (b ? resolve(b) : reject(new Error('encode failed'))), type, quality));
}

export async function encodeImage(img, w, h, type, quality) {
  const c = canvas(w, h); const g = c.getContext('2d');
  if (type === 'image/jpeg') { g.fillStyle = '#fff'; g.fillRect(0, 0, w, h); }   // transparent parts become white
  g.imageSmoothingQuality = 'high';
  g.drawImage(img.source, 0, 0, w, h);
  const blob = await blobOf(c, type, quality);
  if (!blob || (blob.type && blob.type !== type)) return null;   // a browser without this encoder
  return fileBase64(blob);
}

export function fileBase64(blob) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => { const s = String(r.result); resolve(s.slice(s.indexOf(',') + 1)); };
    r.onerror = () => reject(r.error || new Error('read failed'));
    r.readAsDataURL(blob);
  });
}
