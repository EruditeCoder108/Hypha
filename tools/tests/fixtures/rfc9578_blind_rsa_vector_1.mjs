/*
 * Test-vector data from RFC 9578 Appendix A.2, Test Vector 1.
 * https://www.rfc-editor.org/rfc/rfc9578.html#appendix-A.2
 *
 * Copyright (c) 2024 IETF Trust and the persons identified as authors of
 * the code. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of Internet Society, IETF or IETF Trust, nor the names
 *    of specific contributors, may be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

function hex(parts) {
  return Buffer.from(parts.join('').replaceAll(/\s/g, ''), 'hex');
}

export const issuerPublicKeySpki = hex([
  '30820152303d06092a864886f70d01010a3030a00d300b0609608648016503040202',
  'a11a301806092a864886f70d010108300b0609608648016503040202a20302013003',
  '82010f003082010a0282010100cb1aed6b6a95f5b1ce013a4cfcab25b94b2e64a230',
  '34e4250a7eab43c0df3a8c12993af12b111908d4b471bec31d4b6c9ad9cdda90612',
  'a2ee903523e6de5a224d6b02f09e5c374d0cfe01d8f529c500a78a2f67908fa682b',
  '5a2b430c81eaf1af72d7b5e794fc98a3139276879757ce453b526ef9bf6ceb99979',
  'b8423b90f4461a22af37aab0cf5733f7597abe44d31c732db68a181c6cbbe607d8c',
  '0e52e0655fd9996dc584eca0be87afbcd78a337d17b1dba9e828bbd81e291317144',
  'e7ff89f55619709b096cbb9ea474cead264c2073fe49740c01f00e109106066983d',
  '21e5f83f086e2e823c879cd43cef700d2a352a9babd612d03cad02db134b7e225a5',
  'f0203010001',
]);

export const tokenChallenge = hex([
  '0002000e6973737565722e6578616d706c65208e7acc900e393381e8810b7c9e4a68',
  'b5163f1f880ab6688a6ffe780923609e88000e6f726967696e2e6578616d706c65',
]);

export const token = hex([
  '0002aa72019d1f951df197021ce63876fe8b0a02dc1c31a12b0a2dd1508d07827f05',
  '5969f643b4cfda5196d4aa86aeb5368834f4f06de46950ed435b3b81bd036d44',
  'ca572f8982a9ca248a3056186322d93ca147266121ddeb5632c07f1f71cd2708',
  'bc6a21b533d07294b5e900faf5537dd3eb33cee4e08c9670d1e5358fd184b0e00',
  'c637174f5206b14c7bb0e724ebf6b56271e5aa2ed94c051c4a433d302b23bc52',
  '460810d489fb050f9de5c868c6c1b06e3849fd087629f704cc724bc0d0984d5c',
  '339686fcdd75f9a9cdd25f37f855f6f4c584d84f716864f546b696d620c5bd41',
  'a811498de84ff9740ba3003ba2422d26b91eb745c084758974642a42078201543',
  '246ddb58030ea8e722376aa82484dca9610a8fb7e018e396165462e17a03e40e',
  'a7e128c090a911ecc708066cb201833010c1ebd4e910fc8e27a1be467f7867183',
  '6a508257123a45e4e0ae2180a434bd1037713466347a8ebe46439d3da1970',
]);
