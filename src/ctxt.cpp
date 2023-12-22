#include "ctxt.hpp"

using namespace std;
using namespace seal;

WalrusCtxt::WalrusCtxt(scheme_type scheme) {
  // noise budget is set to invalid before encryption
  this->noise_budget = -1;
  this->scheme = scheme;
  this->mult_depth = 0;
  this->add_depth = 0;
  this->scale = 0.0;
}

void WalrusCtxt::WalrusEncryptSingle(Encryptor& encryptor, uint64_t val) {
  encryptor.encrypt(Plaintext(util::uint_to_hex_string(&val, std::size_t(1))), this->ctxt);
}

void WalrusCtxt::WalrusEncryptSingleFloat(Encryptor& encryptor, CKKSEncoder& encoder,
                                          double val, double scale) {
  Plaintext val_plain;
  encoder.encode(val, scale, val_plain);
  encryptor.encrypt(val_plain, this->ctxt);
  this->scale = scale;
}

void WalrusCtxt::WalrusEncryptVector(BatchEncoder& batch_encoder, 
                                     Encryptor& encryptor, vector<uint64_t>& vals) {
  Plaintext vals_plain;
  batch_encoder.encode(vals, vals_plain);
  encryptor.encrypt(vals_plain, this->ctxt);
}

void WalrusCtxt::WalrusEncryptVectorFloat(Encryptor& encryptor, CKKSEncoder& encoder,
                                          vector<double>& val, double scale) {
  Plaintext vals_plain;
  encoder.encode(val, scale, vals_plain);
  encryptor.encrypt(vals_plain, this->ctxt);
  this->scale = scale;
}

uint64_t WalrusCtxt::WalrusDecryptSingle(Decryptor& decryptor) {
  Plaintext result_plain;
  decryptor.decrypt(this->ctxt, result_plain);
  return result_plain.data()[0];
}

double WalrusCtxt::WalrusDecryptSingleFloat(CKKSEncoder& encoder, 
                                            Decryptor& decryptor) {
  Plaintext val_plain;
  vector<double> vals;
  decryptor.decrypt(this->ctxt, val_plain);
  encoder.decode(val_plain, vals);
  return vals[0];
}


vector<uint64_t> WalrusCtxt::WalrusDecryptVector(BatchEncoder& batch_encoder, 
                                     Decryptor& decryptor) {
  vector<uint64_t> result_vec;
  Plaintext result_plain;
  decryptor.decrypt(this->ctxt, result_plain);
  batch_encoder.decode(result_plain, result_vec);
  return result_vec;
}

vector<double> WalrusCtxt::WalrusDecryptVectorFloat(CKKSEncoder& encoder, 
                                                    Decryptor& decryptor) {
  Plaintext val_plain;
  vector<double> vals;
  decryptor.decrypt(this->ctxt, val_plain);
  encoder.decode(val_plain, vals);
  return vals;
}
