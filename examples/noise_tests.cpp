#include "ctxt.hpp"
#include "evaluator.hpp"
#include <cmath>
#include <iostream>

using namespace std;
using namespace seal;

#define NUM_ADDS 62
#define NUM_MULTS 2

int main() {
  EncryptionParameters parms(scheme_type::ckks);
  size_t poly_modulus_degree = 8192;
  parms.set_poly_modulus_degree(poly_modulus_degree);
  parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60}));
  SEALContext context(parms);
  KeyGenerator keygen(context);
  SecretKey secret_key = keygen.secret_key();
  PublicKey public_key;
  keygen.create_public_key(public_key);
  RelinKeys relin_keys;
  keygen.create_relin_keys(relin_keys);
  Encryptor encryptor(context, public_key);
  Evaluator evaluator(context);
  Decryptor decryptor(context, secret_key);

  CKKSEncoder batch_encoder(context);
  size_t slot_count = batch_encoder.slot_count();
  size_t row_size = slot_count / 2;

  double scale = pow(2.0, 40);

  WalrusCtxt ct = WalrusCtxt(scheme_type::ckks);
  vector<double> test_vec(slot_count);
  for (uint64_t i = 0; i < slot_count; i++) {
    test_vec[i] = 1.0;
  }
  Plaintext vec_pt;
  batch_encoder.encode(test_vec, scale, vec_pt);
  ct.WalrusEncryptVectorFloat(encryptor, batch_encoder, test_vec, scale);
  WalrusCtxt ct2 = WalrusCtxt(scheme_type::ckks);
  ct2.WalrusEncryptVectorFloat(encryptor, batch_encoder, test_vec, scale);
  // cout << "Initial Noise Budget: " << decryptor.invariant_noise_budget(ct.ctxt) << endl;
  // for (uint64_t i = 0; i < NUM_ADDS; i++) {
  //   if (i == 0) {
  //     WalrusAdd(ct2, ct, ct, evaluator, true);
  //   } else {
  //     WalrusAdd(ct2, ct2, ct2, evaluator, true);
  //   }
  // }
  // cout << "Noise Budget @ " << NUM_ADDS << " adds: " <<
  // decryptor.invariant_noise_budget(ct2.ctxt) << endl;
  
  for (uint64_t i = 0; i < NUM_MULTS; i++) {
    if (i == 0) {
      WalrusMult(ct2, ct, ct, evaluator, relin_keys, true);
    } else {
      WalrusMult(ct2, ct2, ct2, evaluator, relin_keys, true);
    }
  }
  // cout << "Noise Budget @ " << NUM_MULTS << " mults: " << decryptor.invariant_noise_budget(ct2.ctxt) << endl;

  vector<double> res_vec = ct2.WalrusDecryptVectorFloat(batch_encoder, decryptor);
  bool pass = true;
  if (abs(1.0 - res_vec[0]) > 0.05) {
    cout << res_vec[0] << endl;
    pass = false;
  }
  // if (ct2.add_depth != NUM_ADDS) {
  //   pass = false;
  // }
  if (ct2.mult_depth != NUM_MULTS) {
    pass = false;
  }
  cout << "Mult Noise Tests: ";
  if (pass) {
    cout << "PASS" << endl;
  } else {
    cout << "FAIL" << endl;
  }

  return 0;
}