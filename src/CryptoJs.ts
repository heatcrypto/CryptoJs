import { randomBytes } from "crypto"

/**
 * We replace Math.random here to use crypto randomBytes
 */
var MathReplaceMent = {
  random: function () {
    return randomBytes(8).readUInt32LE() / 0xffffffff;
  },
  floor: Math.floor,
  abs: Math.abs,
  sin: Math.sin,
  sqrt: Math.sqrt,
  pow: Math.pow
}

// ==================================================================================================
// START INCLUDE FILE cryptojs/aes.js
// ==================================================================================================

/*
CryptoJS v3.1.2
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
export var CryptoJS = (function(u?: any, p?: any) {
  var d: any = {},
    l: any = (d.lib = {}),
    s = class {},
    t = (l.Base = <any>{
      extend: function(a: any) {
        s.prototype = this
        var c: any = new s()
        a && c.mixIn(a)
        c.hasOwnProperty("init") ||
          (c.init = function() {
            c.$super.init.apply(this, arguments)
          })
        c.init.prototype = c
        c.$super = this
        return c
      },
      create: function() {
        var a = this.extend()
        a.init.apply(a, arguments)
        return a
      },
      init: function() {},
      mixIn: function(a: any) {
        for (var c in a) a.hasOwnProperty(c) && (this[c] = a[c])
        a.hasOwnProperty("toString") && (this.toString = a.toString)
      },
      clone: function() {
        return this.init.prototype.extend(this)
      }
    }),
    r = (l.WordArray = t.extend({
      init: function(a: any, c: any) {
        a = this.words = a || []
        this.sigBytes = c != p ? c : 4 * a.length
      },
      toString: function(a: any) {
        return (a || v).stringify(this)
      },
      concat: function(a: any) {
        var c = this.words,
          e = a.words,
          j = this.sigBytes
        a = a.sigBytes
        this.clamp()
        if (j % 4)
          for (var k = 0; k < a; k++)
            c[(j + k) >>> 2] |=
              ((e[k >>> 2] >>> (24 - 8 * (k % 4))) & 255) << (24 - 8 * ((j + k) % 4))
        else if (65535 < e.length) for (k = 0; k < a; k += 4) c[(j + k) >>> 2] = e[k >>> 2]
        else c.push.apply(c, e)
        this.sigBytes += a
        return this
      },
      clamp: function() {
        var a = this.words,
          c = this.sigBytes
        a[c >>> 2] &= 4294967295 << (32 - 8 * (c % 4))
        a.length = u.ceil(c / 4)
      },
      clone: function() {
        var a = t.clone.call(this)
        a.words = this.words.slice(0)
        return a
      },
      random: function(a: any) {
        for (var c = [], e = 0; e < a; e += 4) c.push((4294967296 * u.random()) | 0)
        return new r.init(c, a)
      }
    })),
    w: any = (d.enc = {}),
    v = (w.Hex = {
      stringify: function(a: any) {
        var c = a.words
        a = a.sigBytes
        for (var e = [], j = 0; j < a; j++) {
          var k = (c[j >>> 2] >>> (24 - 8 * (j % 4))) & 255
          e.push((k >>> 4).toString(16))
          e.push((k & 15).toString(16))
        }
        return e.join("")
      },
      parse: function(a: any) {
        for (var c = a.length, e: any[] = [], j = 0; j < c; j += 2)
          e[j >>> 3] |= parseInt(a.substr(j, 2), 16) << (24 - 4 * (j % 8))
        return new r.init(e, c / 2)
      }
    }),
    b = (w.Latin1 = {
      stringify: function(a: any) {
        var c = a.words
        a = a.sigBytes
        for (var e = [], j = 0; j < a; j++)
          e.push(String.fromCharCode((c[j >>> 2] >>> (24 - 8 * (j % 4))) & 255))
        return e.join("")
      },
      parse: function(a: any) {
        for (var c = a.length, e: any[] = [], j = 0; j < c; j++)
          e[j >>> 2] |= (a.charCodeAt(j) & 255) << (24 - 8 * (j % 4))
        return new r.init(e, c)
      }
    }),
    x = (w.Utf8 = {
      stringify: function(a: any) {
        try {
          return decodeURIComponent(escape(b.stringify(a)))
        } catch (c) {
          throw Error("Malformed UTF-8 data")
        }
      },
      parse: function(a: any) {
        return b.parse(unescape(encodeURIComponent(a)))
      }
    }),
    q = (l.BufferedBlockAlgorithm = t.extend({
      reset: function() {
        this._data = new r.init()
        this._nDataBytes = 0
      },
      _append: function(a: any) {
        "string" == typeof a && (a = x.parse(a))
        this._data.concat(a)
        this._nDataBytes += a.sigBytes
      },
      _process: function(a: any) {
        var c = this._data,
          e = c.words,
          j = c.sigBytes,
          k = this.blockSize,
          b: any = j / (4 * k),
          b: any = a ? u.ceil(b) : u.max((b | 0) - this._minBufferSize, 0)
        a = b * k
        j = u.min(4 * a, j)
        var q
        if (a) {
          for (q = 0; q < a; q += k) this._doProcessBlock(e, q)
          q = e.splice(0, a)
          c.sigBytes -= j
        }
        return new r.init(q, j)
      },
      clone: function() {
        var a = t.clone.call(this)
        a._data = this._data.clone()
        return a
      },
      _minBufferSize: 0
    }))
  l.Hasher = q.extend({
    cfg: t.extend(),
    init: function(a: any) {
      this.cfg = this.cfg.extend(a)
      this.reset()
    },
    reset: function() {
      q.reset.call(this)
      this._doReset()
    },
    update: function(a: any) {
      this._append(a)
      this._process()
      return this
    },
    finalize: function(a: any) {
      a && this._append(a)
      return this._doFinalize()
    },
    blockSize: 16,
    _createHelper: function(a: any) {
      return function(b: any, e: any) {
        return new a.init(e).finalize(b)
      }
    },
    _createHmacHelper: function(a: any) {
      return function(b: any, e: any) {
        return new n.HMAC.init(a, e).finalize(b)
      }
    }
  })
  var n: any = (d.algo = {})
  return d
})(MathReplaceMent)
;(function() {
  var u = CryptoJS,
    p = u.lib.WordArray
  u.enc.Base64 = {
    stringify: function(d: any) {
      var l = d.words,
        p = d.sigBytes,
        t = this._map
      d.clamp()
      d = []
      for (var r = 0; r < p; r += 3)
        for (
          var w =
              (((l[r >>> 2] >>> (24 - 8 * (r % 4))) & 255) << 16) |
              (((l[(r + 1) >>> 2] >>> (24 - 8 * ((r + 1) % 4))) & 255) << 8) |
              ((l[(r + 2) >>> 2] >>> (24 - 8 * ((r + 2) % 4))) & 255),
            v = 0;
          4 > v && r + 0.75 * v < p;
          v++
        )
          d.push(t.charAt((w >>> (6 * (3 - v))) & 63))
      if ((l = t.charAt(64))) for (; d.length % 4; ) d.push(l)
      return d.join("")
    },
    parse: function(d: any) {
      var l = d.length,
        s = this._map,
        t = s.charAt(64)
      t && ((t = d.indexOf(t)), -1 != t && (l = t))
      t = []
      var r = 0,
        w = 0
      for (; w < l; w++)
        if (w % 4) {
          var v = s.indexOf(d.charAt(w - 1)) << (2 * (w % 4)),
            b = s.indexOf(d.charAt(w)) >>> (6 - 2 * (w % 4))
          t[r >>> 2] |= (v | b) << (24 - 8 * (r % 4))
          r++
        }
      return p.create(t, r)
    },
    _map: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
  }
})()
;(function(u) {
  function p(b: any, n: any, a: any, c: any, e: any, j: any, k: any) {
    b = b + ((n & a) | (~n & c)) + e + k
    return ((b << j) | (b >>> (32 - j))) + n
  }

  function d(b: any, n: any, a: any, c: any, e: any, j: any, k: any) {
    b = b + ((n & c) | (a & ~c)) + e + k
    return ((b << j) | (b >>> (32 - j))) + n
  }

  function l(b: any, n: any, a: any, c: any, e: any, j: any, k: any) {
    b = b + (n ^ a ^ c) + e + k
    return ((b << j) | (b >>> (32 - j))) + n
  }

  function s(b: any, n: any, a: any, c: any, e: any, j: any, k: any) {
    b = b + (a ^ (n | ~c)) + e + k
    return ((b << j) | (b >>> (32 - j))) + n
  }
  for (
    var t = CryptoJS, r = t.lib, w = r.WordArray, v = r.Hasher, r = t.algo, b: any[] = [], x = 0;
    64 > x;
    x++
  )
    b[x] = (4294967296 * u.abs(u.sin(x + 1))) | 0
  r = r.MD5 = v.extend({
    _doReset: function() {
      this._hash = new w.init([1732584193, 4023233417, 2562383102, 271733878])
    },
    _doProcessBlock: function(q: any, n: any) {
      for (let a = 0; 16 > a; a++) {
        var c = n + a,
          e = q[c]
        q[c] = (((e << 8) | (e >>> 24)) & 16711935) | (((e << 24) | (e >>> 8)) & 4278255360)
      }
      var a = this._hash.words,
        c = q[n + 0],
        e = q[n + 1],
        j = q[n + 2],
        k = q[n + 3],
        z = q[n + 4],
        r = q[n + 5],
        t = q[n + 6],
        w = q[n + 7],
        v = q[n + 8],
        A = q[n + 9],
        B = q[n + 10],
        C = q[n + 11],
        u = q[n + 12],
        D = q[n + 13],
        E = q[n + 14],
        x = q[n + 15],
        f = a[0],
        m = a[1],
        g = a[2],
        h = a[3],
        f = p(f, m, g, h, c, 7, b[0]),
        h = p(h, f, m, g, e, 12, b[1]),
        g = p(g, h, f, m, j, 17, b[2]),
        m = p(m, g, h, f, k, 22, b[3]),
        f = p(f, m, g, h, z, 7, b[4]),
        h = p(h, f, m, g, r, 12, b[5]),
        g = p(g, h, f, m, t, 17, b[6]),
        m = p(m, g, h, f, w, 22, b[7]),
        f = p(f, m, g, h, v, 7, b[8]),
        h = p(h, f, m, g, A, 12, b[9]),
        g = p(g, h, f, m, B, 17, b[10]),
        m = p(m, g, h, f, C, 22, b[11]),
        f = p(f, m, g, h, u, 7, b[12]),
        h = p(h, f, m, g, D, 12, b[13]),
        g = p(g, h, f, m, E, 17, b[14]),
        m = p(m, g, h, f, x, 22, b[15]),
        f = d(f, m, g, h, e, 5, b[16]),
        h = d(h, f, m, g, t, 9, b[17]),
        g = d(g, h, f, m, C, 14, b[18]),
        m = d(m, g, h, f, c, 20, b[19]),
        f = d(f, m, g, h, r, 5, b[20]),
        h = d(h, f, m, g, B, 9, b[21]),
        g = d(g, h, f, m, x, 14, b[22]),
        m = d(m, g, h, f, z, 20, b[23]),
        f = d(f, m, g, h, A, 5, b[24]),
        h = d(h, f, m, g, E, 9, b[25]),
        g = d(g, h, f, m, k, 14, b[26]),
        m = d(m, g, h, f, v, 20, b[27]),
        f = d(f, m, g, h, D, 5, b[28]),
        h = d(h, f, m, g, j, 9, b[29]),
        g = d(g, h, f, m, w, 14, b[30]),
        m = d(m, g, h, f, u, 20, b[31]),
        f = l(f, m, g, h, r, 4, b[32]),
        h = l(h, f, m, g, v, 11, b[33]),
        g = l(g, h, f, m, C, 16, b[34]),
        m = l(m, g, h, f, E, 23, b[35]),
        f = l(f, m, g, h, e, 4, b[36]),
        h = l(h, f, m, g, z, 11, b[37]),
        g = l(g, h, f, m, w, 16, b[38]),
        m = l(m, g, h, f, B, 23, b[39]),
        f = l(f, m, g, h, D, 4, b[40]),
        h = l(h, f, m, g, c, 11, b[41]),
        g = l(g, h, f, m, k, 16, b[42]),
        m = l(m, g, h, f, t, 23, b[43]),
        f = l(f, m, g, h, A, 4, b[44]),
        h = l(h, f, m, g, u, 11, b[45]),
        g = l(g, h, f, m, x, 16, b[46]),
        m = l(m, g, h, f, j, 23, b[47]),
        f = s(f, m, g, h, c, 6, b[48]),
        h = s(h, f, m, g, w, 10, b[49]),
        g = s(g, h, f, m, E, 15, b[50]),
        m = s(m, g, h, f, r, 21, b[51]),
        f = s(f, m, g, h, u, 6, b[52]),
        h = s(h, f, m, g, k, 10, b[53]),
        g = s(g, h, f, m, B, 15, b[54]),
        m = s(m, g, h, f, e, 21, b[55]),
        f = s(f, m, g, h, v, 6, b[56]),
        h = s(h, f, m, g, x, 10, b[57]),
        g = s(g, h, f, m, t, 15, b[58]),
        m = s(m, g, h, f, D, 21, b[59]),
        f = s(f, m, g, h, z, 6, b[60]),
        h = s(h, f, m, g, C, 10, b[61]),
        g = s(g, h, f, m, j, 15, b[62]),
        m = s(m, g, h, f, A, 21, b[63])
      a[0] = (a[0] + f) | 0
      a[1] = (a[1] + m) | 0
      a[2] = (a[2] + g) | 0
      a[3] = (a[3] + h) | 0
    },
    _doFinalize: function() {
      var b = this._data,
        n = b.words,
        a = 8 * this._nDataBytes,
        c = 8 * b.sigBytes
      n[c >>> 5] |= 128 << (24 - c % 32)
      var e = u.floor(a / 4294967296)
      n[(((c + 64) >>> 9) << 4) + 15] =
        (((e << 8) | (e >>> 24)) & 16711935) | (((e << 24) | (e >>> 8)) & 4278255360)
      n[(((c + 64) >>> 9) << 4) + 14] =
        (((a << 8) | (a >>> 24)) & 16711935) | (((a << 24) | (a >>> 8)) & 4278255360)
      b.sigBytes = 4 * (n.length + 1)
      this._process()
      b = this._hash
      n = b.words
      for (a = 0; 4 > a; a++)
        (c = n[a]),
          (n[a] = (((c << 8) | (c >>> 24)) & 16711935) | (((c << 24) | (c >>> 8)) & 4278255360))
      return b
    },
    clone: function() {
      var b = v.clone.call(this)
      b._hash = this._hash.clone()
      return b
    }
  })
  t.MD5 = v._createHelper(r)
  t.HmacMD5 = v._createHmacHelper(r)
})(MathReplaceMent)
;(function() {
  var u = CryptoJS,
    p = u.lib,
    d = p.Base,
    l = p.WordArray,
    p = u.algo,
    s = (p.EvpKDF = d.extend({
      cfg: d.extend({
        keySize: 4,
        hasher: p.MD5,
        iterations: 1
      }),
      init: function(d: any) {
        this.cfg = this.cfg.extend(d)
      },
      compute: function(d: any, r: any) {
        for (
          var p = this.cfg,
            s = p.hasher.create(),
            b = l.create(),
            u = b.words,
            q = p.keySize,
            p = p.iterations;
          u.length < q;

        ) {
          n && s.update(n)
          var n = s.update(d).finalize(r)
          s.reset()
          for (var a = 1; a < p; a++) (n = s.finalize(n)), s.reset()
          b.concat(n)
        }
        b.sigBytes = 4 * q
        return b
      }
    }))
  u.EvpKDF = function(d: any, l: any, p: any) {
    return s.create(p).compute(d, l)
  }
})()
CryptoJS.lib.Cipher ||
  (function(u?: any) {
    var p = CryptoJS,
      d = p.lib,
      l = d.Base,
      s = d.WordArray,
      t = d.BufferedBlockAlgorithm,
      r = p.enc.Base64,
      w = p.algo.EvpKDF,
      v = (d.Cipher = t.extend({
        cfg: l.extend(),
        createEncryptor: function(e: any, a: any) {
          return this.create(this._ENC_XFORM_MODE, e, a)
        },
        createDecryptor: function(e: any, a: any) {
          return this.create(this._DEC_XFORM_MODE, e, a)
        },
        init: function(e: any, a: any, b: any) {
          this.cfg = this.cfg.extend(b)
          this._xformMode = e
          this._key = a
          this.reset()
        },
        reset: function() {
          t.reset.call(this)
          this._doReset()
        },
        process: function(e: any) {
          this._append(e)
          return this._process()
        },
        finalize: function(e: any) {
          e && this._append(e)
          return this._doFinalize()
        },
        keySize: 4,
        ivSize: 4,
        _ENC_XFORM_MODE: 1,
        _DEC_XFORM_MODE: 2,
        _createHelper: function(e: any) {
          return {
            encrypt: function(b: any, k: any, d: any) {
              return ("string" == typeof k ? c : a).encrypt(e, b, k, d)
            },
            decrypt: function(b: any, k: any, d: any) {
              return ("string" == typeof k ? c : a).decrypt(e, b, k, d)
            }
          }
        }
      }))
    d.StreamCipher = v.extend({
      _doFinalize: function() {
        return this._process(!0)
      },
      blockSize: 1
    })
    var b: any = (p.mode = {}),
      x = function(e: any, a: any, b: any) {
        // @ts-ignore
        var c = this._iv
        // @ts-ignore
        c ? (this._iv = u) : (c = this._prevBlock)
        for (var d = 0; d < b; d++) e[a + d] ^= c[d]
      },
      q = (d.BlockCipherMode = l.extend({
        createEncryptor: function(e: any, a: any) {
          return this.Encryptor.create(e, a)
        },
        createDecryptor: function(e: any, a: any) {
          return this.Decryptor.create(e, a)
        },
        init: function(e: any, a: any) {
          this._cipher = e
          this._iv = a
        }
      })).extend()
    q.Encryptor = q.extend({
      processBlock: function(e: any, a: any) {
        var b = this._cipher,
          c = b.blockSize
        x.call(this, e, a, c)
        b.encryptBlock(e, a)
        this._prevBlock = e.slice(a, a + c)
      }
    })
    q.Decryptor = q.extend({
      processBlock: function(e: any, a: any) {
        var b = this._cipher,
          c = b.blockSize,
          d = e.slice(a, a + c)
        b.decryptBlock(e, a)
        x.call(this, e, a, c)
        this._prevBlock = d
      }
    })
    b = b.CBC = q
    q = (p.pad = <any>{}).Pkcs7 = {
      pad: function(a: any, b: any) {
        for (
          var c = 4 * b,
            c = c - a.sigBytes % c,
            d = (c << 24) | (c << 16) | (c << 8) | c,
            l = [],
            n = 0;
          n < c;
          n += 4
        )
          l.push(d)
        c = s.create(l, c)
        a.concat(c)
      },
      unpad: function(a: any) {
        a.sigBytes -= a.words[(a.sigBytes - 1) >>> 2] & 255
      }
    }
    d.BlockCipher = v.extend({
      cfg: v.cfg.extend({
        mode: b,
        padding: q
      }),
      reset: function() {
        v.reset.call(this)
        var a = this.cfg,
          b = a.iv,
          a = a.mode
        if (this._xformMode == this._ENC_XFORM_MODE) var c = a.createEncryptor
        else (c = a.createDecryptor), (this._minBufferSize = 1)
        this._mode = c.call(a, this, b && b.words)
      },
      _doProcessBlock: function(a: any, b: any) {
        this._mode.processBlock(a, b)
      },
      _doFinalize: function() {
        var a = this.cfg.padding
        if (this._xformMode == this._ENC_XFORM_MODE) {
          a.pad(this._data, this.blockSize)
          var b = this._process(!0)
        } else (b = this._process(!0)), a.unpad(b)
        return b
      },
      blockSize: 4
    })
    var n = (d.CipherParams = l.extend({
        init: function(a: any) {
          this.mixIn(a)
        },
        toString: function(a: any) {
          return (a || this.formatter).stringify(this)
        }
      })),
      b = ((p.format = <any>{}).OpenSSL = <any>{
        stringify: function(a: any) {
          var b = a.ciphertext
          a = a.salt
          return (a
            ? s
                .create([1398893684, 1701076831])
                .concat(a)
                .concat(b)
            : b
          ).toString(r)
        },
        parse: function(a: any) {
          a = r.parse(a)
          var b = a.words
          if (1398893684 == b[0] && 1701076831 == b[1]) {
            var c = s.create(b.slice(2, 4))
            b.splice(0, 4)
            a.sigBytes -= 16
          }
          return n.create({
            ciphertext: a,
            salt: c
          })
        }
      }),
      a = (d.SerializableCipher = l.extend({
        cfg: l.extend({
          format: b
        }),
        encrypt: function(a: any, b: any, c: any, d: any) {
          d = this.cfg.extend(d)
          var l = a.createEncryptor(c, d)
          b = l.finalize(b)
          l = l.cfg
          return n.create({
            ciphertext: b,
            key: c,
            iv: l.iv,
            algorithm: a,
            mode: l.mode,
            padding: l.padding,
            blockSize: a.blockSize,
            formatter: d.format
          })
        },
        decrypt: function(a: any, b: any, c: any, d: any) {
          d = this.cfg.extend(d)
          b = this._parse(b, d.format)
          return a.createDecryptor(c, d).finalize(b.ciphertext)
        },
        _parse: function(a: any, b: any) {
          return "string" == typeof a ? b.parse(a, this) : a
        }
      })),
      p = ((p.kdf = <any>{}).OpenSSL = <any>{
        execute: function(a: any, b: any, c: any, d: any) {
          d || (d = s.random(8))
          a = w
            .create({
              keySize: b + c
            })
            .compute(a, d)
          c = s.create(a.words.slice(b), 4 * c)
          a.sigBytes = 4 * b
          return n.create({
            key: a,
            iv: c,
            salt: d
          })
        }
      }),
      c = (d.PasswordBasedCipher = a.extend({
        cfg: a.cfg.extend({
          kdf: p
        }),
        encrypt: function(b: any, c: any, d: any, l: any) {
          l = this.cfg.extend(l)
          d = l.kdf.execute(d, b.keySize, b.ivSize)
          l.iv = d.iv
          b = a.encrypt.call(this, b, c, d.key, l)
          b.mixIn(d)
          return b
        },
        decrypt: function(b: any, c: any, d: any, l: any) {
          l = this.cfg.extend(l)
          c = this._parse(c, l.format)
          d = l.kdf.execute(d, b.keySize, b.ivSize, c.salt)
          l.iv = d.iv
          return a.decrypt.call(this, b, c, d.key, l)
        }
      }))
  })()
;(function() {
  for (
    var u = CryptoJS,
      p = u.lib.BlockCipher,
      d = u.algo,
      l: any[] = [],
      s: any[] = [],
      t: any[] = [],
      r: any[] = [],
      w: any[] = [],
      v: any[] = [],
      b: any[] = [],
      x: any[] = [],
      q: any[] = [],
      n: any[] = [],
      a = [],
      c = 0;
    256 > c;
    c++
  )
    a[c] = 128 > c ? c << 1 : (c << 1) ^ 283
  for (var e = 0, j = 0, c = 0; 256 > c; c++) {
    var k = j ^ (j << 1) ^ (j << 2) ^ (j << 3) ^ (j << 4),
      k = (k >>> 8) ^ (k & 255) ^ 99
    l[e] = k
    s[k] = e
    var z = a[e],
      F = a[z],
      G = a[F],
      y = (257 * a[k]) ^ (16843008 * k)
    t[e] = (y << 24) | (y >>> 8)
    r[e] = (y << 16) | (y >>> 16)
    w[e] = (y << 8) | (y >>> 24)
    v[e] = y
    y = (16843009 * G) ^ (65537 * F) ^ (257 * z) ^ (16843008 * e)
    b[k] = (y << 24) | (y >>> 8)
    x[k] = (y << 16) | (y >>> 16)
    q[k] = (y << 8) | (y >>> 24)
    n[k] = y
    e ? ((e = z ^ a[a[a[G ^ z]]]), (j ^= a[a[j]])) : (e = j = 1)
  }
  var H = [0, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54],
    d = (d.AES = p.extend({
      _doReset: function() {
        for (
          var a = this._key,
            c = a.words,
            d = a.sigBytes / 4,
            a = <any>(4 * ((this._nRounds = d + 6) + 1)),
            e: any[] = (this._keySchedule = []),
            j = 0;
          j < a;
          j++
        )
          if (j < d) e[j] = c[j]
          else {
            var k = e[j - 1]
            j % d
              ? 6 < d &&
                4 == j % d &&
                (k =
                  (l[k >>> 24] << 24) |
                  (l[(k >>> 16) & 255] << 16) |
                  (l[(k >>> 8) & 255] << 8) |
                  l[k & 255])
              : ((k = (k << 8) | (k >>> 24)),
                (k =
                  (l[k >>> 24] << 24) |
                  (l[(k >>> 16) & 255] << 16) |
                  (l[(k >>> 8) & 255] << 8) |
                  l[k & 255]),
                (k ^= H[(j / d) | 0] << 24))
            e[j] = e[j - d] ^ k
          }
        c = this._invKeySchedule = []
        for (d = 0; d < a; d++)
          (j = a - d),
            (k = d % 4 ? e[j] : e[j - 4]),
            (c[d] =
              4 > d || 4 >= j
                ? k
                : b[l[k >>> 24]] ^ x[l[(k >>> 16) & 255]] ^ q[l[(k >>> 8) & 255]] ^ n[l[k & 255]])
      },
      encryptBlock: function(a: any, b: any) {
        this._doCryptBlock(a, b, this._keySchedule, t, r, w, v, l)
      },
      decryptBlock: function(a: any, c: any) {
        var d = a[c + 1]
        a[c + 1] = a[c + 3]
        a[c + 3] = d
        this._doCryptBlock(a, c, this._invKeySchedule, b, x, q, n, s)
        d = a[c + 1]
        a[c + 1] = a[c + 3]
        a[c + 3] = d
      },
      _doCryptBlock: function(a: any, b: any, c: any, d: any, e: any, j: any, l: any, f: any) {
        for (
          var m = this._nRounds,
            g = a[b] ^ c[0],
            h = a[b + 1] ^ c[1],
            k = a[b + 2] ^ c[2],
            n = a[b + 3] ^ c[3],
            p = 4,
            r = 1;
          r < m;
          r++
        )
          var q = d[g >>> 24] ^ e[(h >>> 16) & 255] ^ j[(k >>> 8) & 255] ^ l[n & 255] ^ c[p++],
            s = d[h >>> 24] ^ e[(k >>> 16) & 255] ^ j[(n >>> 8) & 255] ^ l[g & 255] ^ c[p++],
            t = d[k >>> 24] ^ e[(n >>> 16) & 255] ^ j[(g >>> 8) & 255] ^ l[h & 255] ^ c[p++],
            n = d[n >>> 24] ^ e[(g >>> 16) & 255] ^ j[(h >>> 8) & 255] ^ l[k & 255] ^ c[p++],
            g = q,
            h = s,
            k = t
        q =
          ((f[g >>> 24] << 24) |
            (f[(h >>> 16) & 255] << 16) |
            (f[(k >>> 8) & 255] << 8) |
            f[n & 255]) ^
          c[p++]
        s =
          ((f[h >>> 24] << 24) |
            (f[(k >>> 16) & 255] << 16) |
            (f[(n >>> 8) & 255] << 8) |
            f[g & 255]) ^
          c[p++]
        t =
          ((f[k >>> 24] << 24) |
            (f[(n >>> 16) & 255] << 16) |
            (f[(g >>> 8) & 255] << 8) |
            f[h & 255]) ^
          c[p++]
        n =
          ((f[n >>> 24] << 24) |
            (f[(g >>> 16) & 255] << 16) |
            (f[(h >>> 8) & 255] << 8) |
            f[k & 255]) ^
          c[p++]
        a[b] = q
        a[b + 1] = s
        a[b + 2] = t
        a[b + 3] = n
      },
      keySize: 8
    }))
  u.AES = p._createHelper(d)
})()

// ==================================================================================================
// END INCLUDE FILE cryptojs/aes.js
// ==================================================================================================

// ==================================================================================================
// START INCLUDE FILE cryptojs/hmac.js
// ==================================================================================================
;(function() {
  // Shortcuts
  var C = CryptoJS
  var C_lib = C.lib
  var Base = C_lib.Base
  var C_enc = C.enc
  var Utf8 = C_enc.Utf8
  var C_algo = C.algo

  /**
   * HMAC algorithm.
   */
  var HMAC = (C_algo.HMAC = Base.extend({
    /**
     * Initializes a newly created HMAC.
     *
     * @param {Hasher} hasher The hash algorithm to use.
     * @param {WordArray|string} key The secret key.
     *
     * @example
     *
     *     var hmacHasher = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA256, key)
     */
    init: function(hasher: any, key: any) {
      // Init hasher
      hasher = this._hasher = new hasher.init()

      // Convert string to WordArray, else assume WordArray already
      if (typeof key == "string") {
        key = Utf8.parse(key)
      }

      // Shortcuts
      var hasherBlockSize = hasher.blockSize
      var hasherBlockSizeBytes = hasherBlockSize * 4

      // Allow arbitrary length keys
      if (key.sigBytes > hasherBlockSizeBytes) {
        key = hasher.finalize(key)
      }

      // Clamp excess bits
      key.clamp()

      // Clone key for inner and outer pads
      var oKey = (this._oKey = key.clone())
      var iKey = (this._iKey = key.clone())

      // Shortcuts
      var oKeyWords = oKey.words
      var iKeyWords = iKey.words

      // XOR keys with pad constants
      for (var i = 0; i < hasherBlockSize; i++) {
        oKeyWords[i] ^= 0x5c5c5c5c
        iKeyWords[i] ^= 0x36363636
      }
      oKey.sigBytes = iKey.sigBytes = hasherBlockSizeBytes

      // Set initial values
      this.reset()
    },

    /**
     * Resets this HMAC to its initial state.
     *
     * @example
     *
     *     hmacHasher.reset()
     */
    reset: function() {
      // Shortcut
      var hasher = this._hasher

      // Reset
      hasher.reset()
      hasher.update(this._iKey)
    },

    /**
     * Updates this HMAC with a message.
     *
     * @param {WordArray|string} messageUpdate The message to append.
     *
     * @return {HMAC} This HMAC instance.
     *
     * @example
     *
     *     hmacHasher.update('message')
     *     hmacHasher.update(wordArray)
     */
    update: function(messageUpdate: any) {
      this._hasher.update(messageUpdate)

      // Chainable
      return this
    },

    /**
     * Finalizes the HMAC computation.
     * Note that the finalize operation is effectively a destructive, read-once operation.
     *
     * @param {WordArray|string} messageUpdate (Optional) A final message update.
     *
     * @return {WordArray} The HMAC.
     *
     * @example
     *
     *     var hmac = hmacHasher.finalize()
     *     var hmac = hmacHasher.finalize('message')
     *     var hmac = hmacHasher.finalize(wordArray)
     */
    finalize: function(messageUpdate: any) {
      // Shortcut
      var hasher = this._hasher

      // Compute HMAC
      var innerHash = hasher.finalize(messageUpdate)
      hasher.reset()
      var hmac = hasher.finalize(this._oKey.clone().concat(innerHash))

      return hmac
    }
  }))
})()

// ==================================================================================================
// END INCLUDE FILE cryptojs/hmac.js
// ==================================================================================================

// ==================================================================================================
// START INCLUDE FILE cryptojs/pbkdf2.js
// ==================================================================================================

/*
CryptoJS v3.1.2
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
;(function() {
  // Shortcuts
  var C = CryptoJS
  var C_lib = C.lib
  var Base = C_lib.Base
  var WordArray = C_lib.WordArray
  var C_algo = C.algo
  var SHA1 = C_algo.SHA1
  var HMAC = C_algo.HMAC

  /**
   * Password-Based Key Derivation Function 2 algorithm.
   */
  var PBKDF2 = (C_algo.PBKDF2 = Base.extend({
    /**
     * Configuration options.
     *
     * @property {number} keySize The key size in words to generate. Default: 4 (128 bits)
     * @property {Hasher} hasher The hasher to use. Default: SHA1
     * @property {number} iterations The number of iterations to perform. Default: 1
     */
    cfg: Base.extend({
      keySize: 128 / 32,
      hasher: SHA1,
      iterations: 1
    }),

    /**
     * Initializes a newly created key derivation function.
     *
     * @param {Object} cfg (Optional) The configuration options to use for the derivation.
     *
     * @example
     *
     *     var kdf = CryptoJS.algo.PBKDF2.create();
     *     var kdf = CryptoJS.algo.PBKDF2.create({ keySize: 8 });
     *     var kdf = CryptoJS.algo.PBKDF2.create({ keySize: 8, iterations: 1000 });
     */
    init: function(cfg: any) {
      this.cfg = this.cfg.extend(cfg)
    },

    /**
     * Computes the Password-Based Key Derivation Function 2.
     *
     * @param {WordArray|string} password The password.
     * @param {WordArray|string} salt A salt.
     *
     * @return {WordArray} The derived key.
     *
     * @example
     *
     *     var key = kdf.compute(password, salt);
     */
    compute: function(password: any, salt: any) {
      // Shortcut
      var cfg = this.cfg

      // Init HMAC
      var hmac = HMAC.create(cfg.hasher, password)

      // Initial values
      var derivedKey = WordArray.create()
      var blockIndex = WordArray.create([0x00000001])

      // Shortcuts
      var derivedKeyWords = derivedKey.words
      var blockIndexWords = blockIndex.words
      var keySize = cfg.keySize
      var iterations = cfg.iterations

      // Generate key
      while (derivedKeyWords.length < keySize) {
        var block = hmac.update(salt).finalize(blockIndex)
        hmac.reset()

        // Shortcuts
        var blockWords = block.words
        var blockWordsLength = blockWords.length

        // Iterations
        var intermediate = block
        for (var i = 1; i < iterations; i++) {
          intermediate = hmac.finalize(intermediate)
          hmac.reset()

          // Shortcut
          var intermediateWords = intermediate.words

          // XOR intermediate with block
          for (var j = 0; j < blockWordsLength; j++) {
            blockWords[j] ^= intermediateWords[j]
          }
        }

        derivedKey.concat(block)
        blockIndexWords[0]++
      }
      derivedKey.sigBytes = keySize * 4

      return derivedKey
    }
  }))

  /**
   * Computes the Password-Based Key Derivation Function 2.
   *
   * @param {WordArray|string} password The password.
   * @param {WordArray|string} salt A salt.
   * @param {Object} cfg (Optional) The configuration options to use for this computation.
   *
   * @return {WordArray} The derived key.
   *
   * @static
   *
   * @example
   *
   *     var key = CryptoJS.PBKDF2(password, salt);
   *     var key = CryptoJS.PBKDF2(password, salt, { keySize: 8 });
   *     var key = CryptoJS.PBKDF2(password, salt, { keySize: 8, iterations: 1000 });
   */
  C.PBKDF2 = function(password: any, salt: any, cfg: any) {
    return PBKDF2.create(cfg).compute(password, salt)
  }
})()

// ==================================================================================================
// END INCLUDE FILE cryptojs/pbkdf2.js
// ==================================================================================================

// ==================================================================================================
// START INCLUDE FILE cryptojs/sha256.js
// ==================================================================================================
;(function(h) {
  for (
    var s = CryptoJS,
      f = s.lib,
      t = f.WordArray,
      g = f.Hasher,
      f = s.algo,
      j: any[] = [],
      q: any[] = [],
      v = function(a: any) {
        return (4294967296 * (a - (a | 0))) | 0
      },
      u = 2,
      k = 0;
    64 > k;

  ) {
    var l
    a: {
      l = u
      for (var x = h.sqrt(l), w = 2; w <= x; w++)
        if (!(l % w)) {
          l = !1
          break a
        }
      l = !0
    }
    l && (8 > k && (j[k] = v(h.pow(u, 0.5))), (q[k] = v(h.pow(u, 1 / 3))), k++)
    u++
  }
  var a: any[] = [],
    f = (f.SHA256 = g.extend({
      _doReset: function() {
        this._hash = new t.init(j.slice(0))
      },
      _doProcessBlock: function(c: any, d: any) {
        for (
          var b = this._hash.words,
            e = b[0],
            f = b[1],
            m = b[2],
            h = b[3],
            p = b[4],
            j = b[5],
            k = b[6],
            l = b[7],
            n = 0;
          64 > n;
          n++
        ) {
          if (16 > n) a[n] = c[d + n] | 0
          else {
            var r = a[n - 15],
              g = a[n - 2]
            a[n] =
              (((r << 25) | (r >>> 7)) ^ ((r << 14) | (r >>> 18)) ^ (r >>> 3)) +
              a[n - 7] +
              (((g << 15) | (g >>> 17)) ^ ((g << 13) | (g >>> 19)) ^ (g >>> 10)) +
              a[n - 16]
          }
          r =
            l +
            (((p << 26) | (p >>> 6)) ^ ((p << 21) | (p >>> 11)) ^ ((p << 7) | (p >>> 25))) +
            ((p & j) ^ (~p & k)) +
            q[n] +
            a[n]
          g =
            (((e << 30) | (e >>> 2)) ^ ((e << 19) | (e >>> 13)) ^ ((e << 10) | (e >>> 22))) +
            ((e & f) ^ (e & m) ^ (f & m))
          l = k
          k = j
          j = p
          p = (h + r) | 0
          h = m
          m = f
          f = e
          e = (r + g) | 0
        }
        b[0] = (b[0] + e) | 0
        b[1] = (b[1] + f) | 0
        b[2] = (b[2] + m) | 0
        b[3] = (b[3] + h) | 0
        b[4] = (b[4] + p) | 0
        b[5] = (b[5] + j) | 0
        b[6] = (b[6] + k) | 0
        b[7] = (b[7] + l) | 0
      },
      _doFinalize: function() {
        var a = this._data,
          d = a.words,
          b = 8 * this._nDataBytes,
          e = 8 * a.sigBytes
        d[e >>> 5] |= 128 << (24 - e % 32)
        d[(((e + 64) >>> 9) << 4) + 14] = h.floor(b / 4294967296)
        d[(((e + 64) >>> 9) << 4) + 15] = b
        a.sigBytes = 4 * d.length
        this._process()
        return this._hash
      },
      clone: function() {
        var a = g.clone.call(this)
        a._hash = this._hash.clone()
        return a
      }
    }))
  s.SHA256 = g._createHelper(f)
  s.HmacSHA256 = g._createHmacHelper(f)
})(MathReplaceMent)

// ==================================================================================================
// END INCLUDE FILE cryptojs/sha256.js
// ==================================================================================================