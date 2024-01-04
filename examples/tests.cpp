#include "ctxt.hpp"
#include "evaluator.hpp"
#include <iostream>

using namespace std;
using namespace seal;

int main() {
  EncryptionParameters parms(scheme_type::bfv);
  size_t poly_modulus_degree = 8192;
  parms.set_poly_modulus_degree(poly_modulus_degree);
  parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
  parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));
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

  BatchEncoder batch_encoder(context);
  size_t slot_count = batch_encoder.slot_count();
  size_t row_size = slot_count / 2;

  WalrusCtxt ct = WalrusCtxt(scheme_type::bfv);
  ct.WalrusEncryptSingle(encryptor, 255);
  uint64_t res = ct.WalrusDecryptSingle(decryptor);
  cout << "Encrypt/Decrypt Scalar Test: ";
  if (res == 255) {
    cout << "PASS" << endl;
  } else {
    cout << "FAIL" << endl;
  }

  vector<uint64_t> test_vec(slot_count);
  for (uint64_t i = 0; i < slot_count; i++) {
    test_vec[i] = i;
  }
  Plaintext vec_pt;
  batch_encoder.encode(test_vec, vec_pt);
  ct.WalrusEncryptVector(batch_encoder, encryptor, test_vec);

  vector<uint64_t> res_vec = ct.WalrusDecryptVector(batch_encoder, decryptor);
  bool pass = true;
  for (uint64_t i = 0; i < slot_count; i++) {
    if (test_vec[i] != res_vec[i]) {
      pass = false;
      break;
    }
  }
  cout << "Encrypt/Decrypt Batched Test: ";
  if (pass) {
    cout << "PASS" << endl;
  } else {
    cout << "FAIL" << endl;
  }

  WalrusCtxt ct2 = WalrusCtxt(scheme_type::bfv);
  WalrusAdd(ct2, ct, ct);
  WalrusAdd(ct2, ct, ct, evaluator);
  res_vec = ct2.WalrusDecryptVector(batch_encoder, decryptor);
  pass = true;
  for (uint64_t i = 0; i < slot_count; i++) {
    if ((test_vec[i] + test_vec[i]) != res_vec[i]) {
      pass = false;
      break;
    }
  }
  if (ct2.add_depth != 1) {
    pass = false;
  }
  cout << "Batched Add Test: ";
  if (pass) {
    cout << "PASS" << endl;
  } else {
    cout << "FAIL" << endl;
  }
  WalrusAddPlain(ct2, ct, vec_pt);
  WalrusAddPlain(ct2, ct, vec_pt, evaluator);
  res_vec = ct2.WalrusDecryptVector(batch_encoder, decryptor);
  pass = true;
  for (uint64_t i = 0; i < slot_count; i++) {
    if ((test_vec[i] + test_vec[i]) != res_vec[i]) {
      pass = false;
      break;
    }
  }
  if (ct2.add_depth != 0) {
    pass = false;
  }
  cout << "Batched Add Plain Test: ";
  if (pass) {
    cout << "PASS" << endl;
  } else {
    cout << "FAIL" << endl;
  }

  WalrusMult(ct2, ct, ct);  
  WalrusMult(ct2, ct, ct, evaluator, relin_keys);
  res_vec = ct2.WalrusDecryptVector(batch_encoder, decryptor);
  pass = true;
  for (uint64_t i = 0; i < 1000; i++) {
    if ((test_vec[i] * test_vec[i]) != res_vec[i]) {
      pass = false;
      break;
    }
  }
  if (ct2.mult_depth != 1) {
    pass = false;
  }
  cout << "Batched Mult Test: ";
  if (pass) {
    cout << "PASS" << endl;
  } else {
    cout << "FAIL" << endl;
  }

  WalrusMultPlain(ct2, ct, vec_pt);
  WalrusMultPlain(ct2, ct, vec_pt, evaluator);
  res_vec = ct2.WalrusDecryptVector(batch_encoder, decryptor);
  pass = true;
  for (uint64_t i = 0; i < 1000; i++) {
    if ((test_vec[i] * test_vec[i]) != res_vec[i]) {
      pass = false;
      break;
    }
  }
  if (ct2.mult_depth != 1) {
    pass = false;
  }
  cout << "Batched Mult Plain Test: ";
  if (pass) {
    cout << "PASS" << endl;
  } else {
    cout << "FAIL" << endl;
  }

  return 0;
}