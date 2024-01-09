#include "ctxt.hpp"
#include "evaluator.hpp"
#include "parameterizer.hpp"
#include <random>
#include <iostream>
#include <ctime>
#include <ratio>
#include <chrono>

using namespace std;
using namespace std::chrono;
using namespace seal;

EncryptionParameters cloud_first_pass(vector<WalrusCtxt>& input_ct) {
  // Chi Squared has four outputs: α, β1, β2, β3
  vector<WalrusCtxt> output_variables(4);
  for (int i = 0; i < 4; i++) {
    output_variables[i] = WalrusCtxt(scheme_type::bgv);
  }

  // Create temp variables to hold specific intermediate values
  WalrusCtxt tmp = WalrusCtxt(scheme_type::bgv);
  WalrusCtxt tmp_2 = WalrusCtxt(scheme_type::bgv);

  // Create constants
  uint64_t four = 4;
  uint64_t two = 2;
  Plaintext pt_four = Plaintext(util::uint_to_hex_string(&four, size_t(1)));
  Plaintext pt_two = Plaintext(util::uint_to_hex_string(&two, size_t(1)));

  // Compute α
  WalrusMultPlain(output_variables[0], input_ct[0], pt_four);
  WalrusMult(output_variables[0], output_variables[0], input_ct[2]);
  WalrusMult(tmp, input_ct[1], input_ct[1]);
  WalrusSub(output_variables[0], output_variables[0], tmp);
  WalrusMult(output_variables[0], output_variables[0], output_variables[0]);

  // Compute β1
  WalrusMultPlain(output_variables[1], input_ct[0], pt_two);
  WalrusAdd(tmp, output_variables[1], input_ct[1]);
  WalrusMult(output_variables[1], tmp, tmp);
  WalrusMultPlain(output_variables[1], output_variables[1], pt_two);

  // Compute β2
  WalrusMultPlain(output_variables[2], input_ct[2], pt_two);
  WalrusAdd(tmp_2, output_variables[2], input_ct[1]);
  WalrusMult(output_variables[2], tmp_2, tmp);

  // Compute β3
  WalrusMult(output_variables[3], tmp_2, tmp_2);
  WalrusMultPlain(output_variables[3], output_variables[3], pt_two);

  return WalrusParameterize(output_variables);
}

vector<WalrusCtxt> cloud_second_pass(Encryptor& encryptor, Evaluator& evaluator, RelinKeys& relin_keys, vector<WalrusCtxt>& input_ct) {
  // Chi Squared has four outputs: α, β1, β2, β3
  vector<WalrusCtxt> output_variables(4);
  for (int i = 0; i < 4; i++) {
    output_variables[i] = WalrusCtxt(scheme_type::bgv);
  }

  // Create temp variables to hold specific intermediate values
  WalrusCtxt tmp = WalrusCtxt(scheme_type::bgv);
  WalrusCtxt tmp_2 = WalrusCtxt(scheme_type::bgv);

  // Create constants
  uint64_t four = 4;
  uint64_t two = 2;
  Plaintext pt_four = Plaintext(util::uint_to_hex_string(&four, size_t(1)));
  Plaintext pt_two = Plaintext(util::uint_to_hex_string(&two, size_t(1)));

  // Compute α
  WalrusMultPlain(output_variables[0], input_ct[0], pt_four, evaluator);
  WalrusMult(output_variables[0], output_variables[0], input_ct[2], evaluator, relin_keys);
  WalrusMult(tmp, input_ct[1], input_ct[1], evaluator, relin_keys);
  WalrusSub(output_variables[0], output_variables[0], tmp, evaluator);
  WalrusMult(output_variables[0], output_variables[0], output_variables[0], evaluator, relin_keys);

  // Compute β1
  WalrusMultPlain(output_variables[1], input_ct[0], pt_two, evaluator);
  WalrusAdd(tmp, output_variables[1], input_ct[1], evaluator);
  WalrusMult(output_variables[1], tmp, tmp, evaluator, relin_keys);
  WalrusMultPlain(output_variables[1], output_variables[1], pt_two, evaluator);

  // Compute β2
  WalrusMultPlain(output_variables[2], input_ct[2], pt_two, evaluator);
  WalrusAdd(tmp_2, output_variables[2], input_ct[1], evaluator);
  WalrusMult(output_variables[2], tmp_2, tmp, evaluator, relin_keys);

  // Compute β3
  WalrusMult(output_variables[3], tmp_2, tmp_2, evaluator, relin_keys);
  WalrusMultPlain(output_variables[3], output_variables[3], pt_two, evaluator);

  return output_variables;
}

void client() {
  // Declare ptxt inputs (N0, N1, N2)
  vector<uint64_t> pt_inputs(3);
  pt_inputs[0] = 2;
  pt_inputs[1] = 7;
  pt_inputs[2] = 9;
  // Create ciphertext objects for parameterization
  vector<WalrusCtxt> inputs(3);
  for (size_t i = 0; i < 3; i++) {
    inputs[i] = WalrusCtxt(scheme_type::bgv);
  }
  // Get optimal parameters from Walrus (running on the cloud)
  EncryptionParameters parms = cloud_first_pass(inputs);
  // Set up SEAL context, keys, and engines based on parameters
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
  // Encrypt batched inputs 
  size_t slot_count = batch_encoder.slot_count();
  for (size_t i = 0; i < 3; i++) {
    vector<uint64_t> in_vec(slot_count);
    for (size_t j = 0; j < slot_count; j++) {
      in_vec[j] = pt_inputs[i];
    }
    inputs[i].WalrusEncryptVector(batch_encoder, encryptor, in_vec);
  }
  // Run encrypted inference on the cloud
  high_resolution_clock::time_point t1 = high_resolution_clock::now();
  vector<WalrusCtxt> enc_res = cloud_second_pass(encryptor, evaluator, relin_keys, inputs);
  high_resolution_clock::time_point t2 = high_resolution_clock::now();
  duration<double> time_span = duration_cast<duration<double>>(t2 - t1);
  std::cout << "Chi Squared Latency: " << time_span.count() << " seconds" << endl;;
  std::cout << "Chi Squared Amortized Latency: " << time_span.count() / slot_count << " seconds" << endl;

  // Decrypt results
  for (size_t i = 0; i < enc_res.size(); i++) {
    auto res_vec = enc_res[i].WalrusDecryptVector(batch_encoder, decryptor);
    if (i == 0) {
      cout << "α: " << res_vec[0] << endl;
    }
    else {
      cout << "β" << i << ": " << res_vec[0] << endl;
    }
  }
  return;
}

int main() {
  client();
  return 0;
}