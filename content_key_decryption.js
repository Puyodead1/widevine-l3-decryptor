/*
This is where the magic happens
*/

var WidevineCrypto = {};

(function () {
  // The public 2048-bit RSA key Widevine uses for Chrome devices in L3, on Windows
  WidevineCrypto.chromeRSAPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtdHcRBiDWWxdJyKDLTPO9OTapumVnW+9g6k3RSflM0CESFEufZUJGC73UKe9e+u789HVZT04pB5or3WB0XOx
aOibJklLBkd7Yfn1OndVrenMKTE1F4/6jg5rmwyv4qFQ1u8M/ThZUrAgb8pTmKfb9vrv1V8AApwVzcQg3s48eESnKjBU99Vk8alPTjPSfOgoTDluGxQONWiwCaMwftNs
YrOzlde+V3UOb5FVzPcrOmaERfyujV3h4sHGRbTCsqYVwMalO7hmNmtemwt0xBuf5Juia7t1scuJypQ8lI1iEsB+JZVo3Uovfa9nNX0gl5TAq1tAh6M55/ttpWAirWHv
CQIDAQAB
-----END PUBLIC KEY-----`;

  // The private 2048-bit RSA key Widevine uses for authenticating Chrome devices in L3, on Windows
  // Extracted by applying some mathematical tricks to Arxan's white-box algorithm
  WidevineCrypto.chromeRSAPrivateKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC10dxEGINZbF0nIoMtM8705Nqm6ZWdb72DqTdFJ+UzQIRIUS59lQkYLvdQp71767vz0dVlPTikHmiv
dYHRc7Fo6JsmSUsGR3th+fU6d1Wt6cwpMTUXj/qODmubDK/ioVDW7wz9OFlSsCBvylOYp9v2+u/VXwACnBXNxCDezjx4RKcqMFT31WTxqU9OM9J86ChMOW4bFA41aLAJ
ozB+02xis7OV175XdQ5vkVXM9ys6ZoRF/K6NXeHiwcZFtMKyphXAxqU7uGY2a16bC3TEG5/km6Jru3Wxy4nKlDyUjWISwH4llWjdSi99r2c1fSCXlMCrW0CHoznn+22l
YCKtYe8JAgMBAAECggEAGOPDJvFCHd43PFG9qlTyylR/2CSWzigLRfhGsClfd24oDaxLVHav+YcIZRqpVkr1flGlyEeittjQ1OAdptoTGbzp7EpRQmlLqyRoHRpT+MxO
Hf91+KVFk+fGdEG+3CPgKKQt34Y0uByTPCpy2i10b7F3Xnq0Sicq1vG33DhYT9A/DRIjYr8Y0AVovq0VDjWqA1FW5OO9p7vky6e+PDMjSHucQ+uaLzVZSc7vWOh0tH5M
0GVk17YpBiB/iTpw4zBUIcaneQX3eaIfSCDHK0SCD6IRF7kl+uORzvWqiWlGzpdG2B96uyP4hd3WoPcZntM79PKm4dAotdgmalbueFJfpwKBgQDUy0EyA9Fq0aPF4LID
HqDPduIm4hEAZf6sQLd8Fe6ywM4p9KOEVx7YPaFxQHFSgIiWXswildPJl8Cg5cM2EyMU1tdn5xaR4VIDk8e2JEDfhPtaWskpJp2rU2wHvAXOeAES7UFMrkhKVqqVOdbo
IhlLdcYp5KxiJ3mwINSSO94ShwKBgQDavJvF+c8AINfCaMocUX0knXz+xCwdP430GoPQCHa1rUj5bZ3qn3XMwSWa57J4x3pVhYmgJv4jpEK+LBULFezNLV5N4C7vH63a
Zo4OF7IUedFBS5B508yAq7RiPhN2VOC8LRdDh5oqnFufjafF82y9d+/czCrVIG43D+KO2j4F7wKBgDg/HZWF0tYEYeDNGuCeOO19xBt5B/tt+lo3pQhkl7qiIhyO8KXr
jVilOcZAvXOMTA5LMnQ13ExeE2m0MdxaRJyeiUOKnrmisFYHuvNXM9qhQPtKIgABmA2QOG728SX5LHd/RRJqwur7a42UQ00Krlr235F1Q2eSfaTjmKyqrHGDAoGAOTrd
2ueoZFUzfnciYlRj1L+r45B6JlDpmDOTx0tfm9sx26j1h1yfWqoyZ5w1kupGNLgSsSdimPqyR8WK3/KlmW1EXkXIoeH8/8aTZlaGzlqtCFN4ApgKyqOiN44cU3qTrkhx
7MY+7OUqB83tVpqBGfWWeYOltUud6qQqV8v8LFsCgYEAnOq+Ls83CaHIWCjpVfiWC+R7mqW+ql1OGtoaajtA4AzhXzX8HIXpYjupPBlXlQ1FFfPem6jwa1UTZf8CpIb8
pPULAN9ZRrxG8V+bvkZWVREPTZj7xPCwPaZHNKoAmi3Dbv7S5SEYDbBX/NyPCLE4sj/AgTPbUsUtaiw5TvrPsFE=
-----END PRIVATE KEY-----`;

  WidevineCrypto.initializeKeys = async function () {
    // load the device RSA keys for various purposes
    this.publicKeyEncrypt = await crypto.subtle.importKey(
      "spki",
      PEM2Binary(this.chromeRSAPublicKey),
      { name: "RSA-OAEP", hash: { name: "SHA-1" } },
      true,
      ["encrypt"]
    );
    this.publicKeyVerify = await crypto.subtle.importKey(
      "spki",
      PEM2Binary(this.chromeRSAPublicKey),
      { name: "RSA-PSS", hash: { name: "SHA-1" } },
      true,
      ["verify"]
    );
    this.privateKeyDecrypt = await crypto.subtle.importKey(
      "pkcs8",
      PEM2Binary(this.chromeRSAPrivateKey),
      { name: "RSA-OAEP", hash: { name: "SHA-1" } },
      true,
      ["decrypt"]
    );

    var isRSAGood = await isRSAConsistent(
      this.publicKeyEncrypt,
      this.privateKeyDecrypt
    );
    if (!isRSAGood) {
      throw "Can't verify RSA keys consistency; This means the public key does not match the private key!";
    }

    this.keysInitialized = true;
  };

  WidevineCrypto.decryptContentKey = async function (
    licenseRequest,
    licenseResponse
  ) {
    // if (
    //   !window.ws ||
    //   window.ws.readyState === window.ws.CLOSED ||
    //   window.ws.readyState === window.ws.CLOSING
    // ) {
    //   window.ws = new WebSocket("ws://127.0.0.1:8080");
    // }

    licenseRequest = SignedMessage.read(new Pbf(licenseRequest));
    licenseResponse = SignedMessage.read(new Pbf(licenseResponse));

    if (licenseRequest.type != SignedMessage.MessageType.LICENSE_REQUEST.value)
      return;

    license = License.read(new Pbf(licenseResponse.msg));

    if (!this.keysInitialized) await this.initializeKeys();

    // make sure the signature in the license request validates under the private key
    var signatureVerified = await window.crypto.subtle.verify(
      { name: "RSA-PSS", saltLength: 20 },
      this.publicKeyVerify,
      licenseRequest.signature,
      licenseRequest.msg
    );
    if (!signatureVerified) {
      console.log(
        "Can't verify license request signature; either the platform is wrong or the key has changed!"
      );
      return null;
    }

    // decrypt the session key
    var sessionKey = await crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      this.privateKeyDecrypt,
      licenseResponse.session_key
    );

    // calculate context_enc
    var encoder = new TextEncoder();
    var keySize = 128;
    var context_enc = concatBuffers([
      [0x01],
      encoder.encode("ENCRYPTION"),
      [0x00],
      licenseRequest.msg,
      intToBuffer(keySize),
    ]);

    // calculate encrypt_key using CMAC
    var encryptKey = wordToByteArray(
      CryptoRipperLib.CMAC(
        arrayToWordArray(new Uint8Array(sessionKey)),
        arrayToWordArray(new Uint8Array(context_enc))
      ).words
    );

    // iterate the keys we got to find those we want to decrypt (the content key(s))
    const keys = [];
    var contentKeys = [];
    for (currentKey of license.key) {
      if (currentKey.type != License.KeyContainer.KeyType.CONTENT.value)
        continue;

      var keyId = currentKey.id;
      var keyData = currentKey.key.slice(0, 16);
      var keyIv = currentKey.iv.slice(0, 16);

      // finally decrypt the content key
      var decryptedKey = wordToByteArray(
        CryptoRipperLib.AES.decrypt(
          { ciphertext: arrayToWordArray(keyData) },
          arrayToWordArray(encryptKey),
          { iv: arrayToWordArray(keyIv) }
        ).words
      );

      contentKeys.push(decryptedKey);
      console.log(
        "WidevineDecryptor: Found key: " +
          toHexString(decryptedKey) +
          " (KID=" +
          toHexString(keyId) +
          ")"
      );
      keys.push({ key: toHexString(decryptedKey), kid: toHexString(keyId) });
    }

    // if (window.location.href.toLowerCase().includes("netflix")) {
    //   // GET MANIFEST
    //   const manifest = await window.getManifest();

    //   if (manifest.video_tracks.length > 1) {
    //     console.warn(`There are ${manifest.video_tracks.length} video tracks!`);
    //   }

    //   const audioStreams = manifest.audio_tracks
    //     .find((x) => x.language === "en" && x.rawTrackType === "primary")
    //     .streams.filter((x) => x.trackType === "PRIMARY");
    //   const audioStream = audioStreams[audioStreams.length - 1];
    //   const videoStream =
    //     manifest.video_tracks[0].streams[
    //       manifest.video_tracks[0].streams.length - 1
    //     ];
    //   const key = videoStream.drmHeaderId;
    //   console.log(
    //     `Highest stream resolution is ${videoStream.res_h}x${videoStream.res_w}`
    //   );

    //   const metadata = await window.getMetadata();

    //   var outFileName;
    //   if (metadata.video.type === "show") {
    //     var curr = metadata.video.currentEpisode;
    //     var season = metadata.video.seasons.find((x) =>
    //       x.episodes.find((x) => x.id === curr)
    //     );
    //     var episode = season.episodes.find((x) => x.id === curr);
    //     outFileName = `${metadata.video.title}.S${season.seq}.E${episode.seq}-${episode.title}.mp4`;
    //   } else if (metadata.video.type === "movie") {
    //     outFileName = `${metadata.video.title}.mp4`;
    //   } else {
    //     console.warn("unknown video type");
    //     outFileName = `unknown.mp4`;
    //   }

    //   window.ws.send(
    //     JSON.stringify({
    //       platform: "netflix",
    //       metadata,
    //       manifest: {
    //         audioStream,
    //         videoStream,
    //         key,
    //         keys,
    //         outFileName,
    //       },
    //     })
    //   );
    // } else if (window.location.href.toLowerCase().includes("hulu")) {
    //   const manifest = window.manifest;
    //   const metadata = window.metadata;
    //   const metadataPre = window.metadataPre;

    //   var outFileName;
    //   if (metadataPre.href_type === "series") {
    //     var curr = metadataPre.id;
    //     const seasons = metadata.components.find((x) => x.name === "Episodes")
    //       .items;
    //     var season = seasons.find((x) =>
    //       x.items.find((x) => x.id === metadataPre.id)
    //     );
    //     var episode = season.items.find((x) => x.id === metadataPre.id);
    //     const seasonShortname =
    //       episode.season.length === 1
    //         ? `S0${episode.season}`
    //         : `S${episode.season}`;
    //     const episodeShortname =
    //       episode.number.length === 1
    //         ? `E0${episode.number}`
    //         : `E${episode.number}`;
    //     outFileName = `${episode.series_name}.S${seasonShortname}.E${episodeShortname.number}-${episode.name}.WEB.%QUALITY%.mp4`;
    //   } else if (metadata.video.type === "movie") {
    //     outFileName = `${metadata.video.title}.mp4`;
    //   } else {
    //     console.warn("unknown video type: " + metadataPre.href_type);
    //     outFileName = `unknown.mp4`;
    //   }

    //   window.ws.send(
    //     JSON.stringify({
    //       platform: "hulu",
    //       manifest,
    //       metadata,
    //       metadataPre,
    //       outFileName,
    //       keys,
    //     })
    //   );
    // } else if (window.location.href.toLowerCase().includes("hbomax")) {
    //   console.debug("platform is hbomax");
    // } else {
    //   console.error("Unknown platform");
    // }

    if (window.location.href.includes("netflix")) {
      //
      console.log("Detected Netflix");
      await processNetflix(keys);
    } else if (window.location.href.includes("hulu")) {
      //
      console.log("Detected Hulu");
      await processHulu(keys);
    } else if (window.location.href.includes("hbomax")) {
      //
      console.log("Detected HBO Max");
      await processHBO(keys);
    } else if (window.location.href.includes("spotify")) {
      //
      console.log("Detected Spotify");
      await processSpotify(keys);
    } else if (window.location.href.includes("amazon")) {
      //
      console.log("Detected Amazon Prime");
      if (!window.requestSent) {
        await processAmazon(keys);
      } else {
        console.warn("Request was already sent!");
      }
    } else {
      console.error("Platform not supported");
    }

    return contentKeys[0];
  };

  async function processNetflix(keys) {
    //console.error("Netflix support is not implemented");
    const manifest = await window.getManifest();
    if (!manifest) {
      console.error("No manifest");
      return;
    }

    if (manifest.video_tracks.length > 1) {
      console.debug(
        `[Downloader] Found ${manifest.video_tracks.length} video tracks.`
      );
    }

    const audioStreams = manifest.audio_tracks
      .find((x) => x.language === "en" && x.rawTrackType === "primary")
      .streams.filter((x) => x.trackType === "PRIMARY");
    const audioStream = audioStreams[audioStreams.length - 1];
    const videoStream =
      manifest.video_tracks[0].streams[
        manifest.video_tracks[0].streams.length - 1
      ];
    const kid = videoStream.drmHeaderId;
    console.log(
      `[Downloader] Highest resolution is${videoStream.res_w}x${videoStream.res_h}`
    );

    const metadata = await window.getMetadata();

    if (!metadata) {
      console.error("No metadata");
      return;
    }

    var outputFileName;
    if (metadata.video.type === "show") {
      var curr = metadata.video.currentEpisode;
      var season = metadata.video.seasons.find((x) =>
        x.episodes.find((x) => x.id === curr)
      );
      var episode = season.episodes.find((x) => x.id === curr);
      outputFileName = `${metadata.video.title}.S${season.seq}.E${episode.seq}.${episode.title}.WEB.${videoStream.res_h}.mp4`;
    } else if (metadata.video.type === "movie") {
      outputFileName = `${metadata.video.title}.WEB.${videoStream.res_h}.mp4`;
    } else {
      console.warn("unknown video type");
      outputFileName = `unknown-${makeid()}.WEB.${videoStream.res_h}.mp4`;
    }

    await sendData({
      platform: "netflix",
      metadata,
      manifest: {
        audioStream,
        videoStream,
      },
	  keys,
	  outputFileName,
	  kid
    })
      .then(() => console.log(`[Downloader] Download request sent`))
      .catch((e) =>
        console.error(`[Downloader] Failed to send data to downloader!`, e)
      );
  }

  async function processHulu(keys) {
    const payload = window.payload;
    if (!payload)
      throw new Error("No payload was found. Is the Hulu extension loaded?");

    // var outFileName;
    // if (metadataPre.href_type === "series") {
    //   var curr = metadataPre.id;
    //   const seasons = metadata.components.find((x) => x.name === "Episodes")
    //     .items;
    //   var season = seasons.find((x) =>
    //     x.items.find((y) => y.id === metadataPre.id)
    //   );
    //   var episode = season.items.find((x) => x.id === metadataPre.id);
    //   const seasonShortname =
    //     episode.season.length === 1
    //       ? `S0${episode.season}`
    //       : `S${episode.season}`;
    //   const episodeShortname =
    //     episode.number.length === 1
    //       ? `E0${episode.number}`
    //       : `E${episode.number}`;
    //   outFileName = `${episode.series_name}.S${seasonShortname}.E${episodeShortname.number}-${episode.name}.WEB.%QUALITY%.mp4`;
    // } else if (metadata.video.type === "movie") {
    //   outFileName = `${metadata.video.title}.mp4`;
    // } else {
    //   console.warn("unknown video type: " + metadataPre.href_type);
    //   outFileName = `unknown.mp4`;
    // }

    await sendData({
      platform: "hulu",
      ...payload,
      keys,
    })
      .then(() => console.log(`[Downloader] Download request sent`))
      .catch((e) =>
        console.error(`[Downloader] Failed to send data to downloader!`, e)
      );

    // window.ws.send(
    //   JSON.stringify({
    //     platform: "hulu",
    //     manifest,
    //     metadata,
    //     metadataPre,
    //     outFileName,
    //     keys,
    //   })
    // );
  }

  async function processHBO(keys) {
    console.error("HBO support is not implemented");
  }

  async function processSpotify(keys) {
    console.error("Spotify support is not implemented");
  }

  async function processAmazon(keys) {
    const asin = window.location.href.split("/")[6].split("?")[0];

    await sendData({
      platform: "amazon",
      asin,
      keys,
    })
      .then(() => console.log(`[Downloader] Download request sent`))
      .catch((e) =>
        console.error(`[Downloader] Failed to send data to downloader!`, e)
      );

    window.requestSent = true;
  }

  function sendData(payload) {
    return new Promise((resolve, reject) => {
      fetch("http://127.0.0.1:5000/rip", {
        method: "POST",
        body: JSON.stringify(payload),
        headers: {
          "Content-Type": "application/json",
        },
      })
        .then(async (r) => {
          if (r.ok) resolve();
          else reject(`${r.status}; ${await r.text()}`);
        })
        .catch((e) => reject(e));
    });
  }

  //
  // Helper functions
  //

  function makeid() {
    var result = "";
    var characters =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    var charactersLength = characters.length;
    for (var i = 0; i < 8; i++) {
      result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
  }

  async function isRSAConsistent(publicKey, privateKey) {
    // See if the data is correctly decrypted after encryption
    var testData = new Uint8Array([0x41, 0x42, 0x43, 0x44]);
    var encryptedData = await crypto.subtle.encrypt(
      { name: "RSA-OAEP" },
      publicKey,
      testData
    );
    var testDecryptedData = await crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      privateKey,
      encryptedData
    );

    return areBuffersEqual(testData, testDecryptedData);
  }

  function areBuffersEqual(buf1, buf2) {
    if (buf1.byteLength != buf2.byteLength) return false;
    var dv1 = new Int8Array(buf1);
    var dv2 = new Int8Array(buf2);
    for (var i = 0; i != buf1.byteLength; i++) {
      if (dv1[i] != dv2[i]) return false;
    }
    return true;
  }

  function concatBuffers(arrays) {
    // Get the total length of all arrays.
    let length = 0;
    arrays.forEach((item) => {
      length += item.length;
    });

    // Create a new array with total length and merge all source arrays.
    let mergedArray = new Uint8Array(length);
    let offset = 0;
    arrays.forEach((item) => {
      mergedArray.set(new Uint8Array(item), offset);
      offset += item.length;
    });

    return mergedArray;
  }

  // CryptoJS format to byte array
  function wordToByteArray(wordArray) {
    var byteArray = [],
      word,
      i,
      j;
    for (i = 0; i < wordArray.length; ++i) {
      word = wordArray[i];
      for (j = 3; j >= 0; --j) {
        byteArray.push((word >> (8 * j)) & 0xff);
      }
    }
    return byteArray;
  }

  // byte array to CryptoJS format
  function arrayToWordArray(u8Array) {
    var words = [],
      i = 0,
      len = u8Array.length;

    while (i < len) {
      words.push(
        (u8Array[i++] << 24) |
          (u8Array[i++] << 16) |
          (u8Array[i++] << 8) |
          u8Array[i++]
      );
    }

    return {
      sigBytes: len,
      words: words,
    };
  }

  const toHexString = (bytes) =>
    bytes.reduce((str, byte) => str + byte.toString(16).padStart(2, "0"), "");

  const intToBuffer = (num) => {
    let b = new ArrayBuffer(4);
    new DataView(b).setUint32(0, num);
    return Array.from(new Uint8Array(b));
  };

  function PEM2Binary(pem) {
    var encoded = "";
    var lines = pem.split("\n");
    for (var i = 0; i < lines.length; i++) {
      if (lines[i].indexOf("-----") < 0) {
        encoded += lines[i];
      }
    }
    var byteStr = atob(encoded);
    var bytes = new Uint8Array(byteStr.length);
    for (var i = 0; i < byteStr.length; i++) {
      bytes[i] = byteStr.charCodeAt(i);
    }
    return bytes.buffer;
  }
})();
