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

#define IO_LEN 100
#define NUM_HIDDEN_NEURONS 25

vector<vector<Plaintext>> cloud_weights;

void cloud_generate_weights() {
  // Create generator for non-zero random 4-bit numbers
  random_device rd;
  mt19937 gen(rd());
  uniform_int_distribution<uint64_t> distribution(1, 15);

  // Generate random numbers and convert to SEAL Plaintexts
  for (int i = 0; i < 2; i++) {
    vector<Plaintext> layer_weights;
    for (int j = 0; j < IO_LEN*NUM_HIDDEN_NEURONS; j++) {
      uint64_t sample = distribution(gen);
      layer_weights.push_back(Plaintext(util::uint_to_hex_string(&sample, size_t(1))));
    }
    cloud_weights.push_back(layer_weights);
  }
}

EncryptionParameters cloud_first_pass(vector<WalrusCtxt>& input_ct) {
  vector<WalrusCtxt> hidden_neurons(NUM_HIDDEN_NEURONS);
  vector<WalrusCtxt> out_neurons(IO_LEN);

  // First Fully-Connected Layer 
  for (int i = 0; i < NUM_HIDDEN_NEURONS; i++) {
    hidden_neurons[i] = WalrusCtxt(scheme_type::bgv);
    for (int j = 0; j < IO_LEN; j++) {
      WalrusCtxt tmp = WalrusCtxt(scheme_type::bgv);
      WalrusMultPlain(tmp, input_ct[j], cloud_weights[0][i*IO_LEN+j]);
      WalrusAdd(hidden_neurons[i], hidden_neurons[i], tmp);
    }
  }

  // Activation Function (x^2)
  for (int i = 0; i < NUM_HIDDEN_NEURONS; i++) {
    WalrusMult(hidden_neurons[i], hidden_neurons[i], hidden_neurons[i]);
  }

  // Second Fully-Connected Layer
  for (int i = 0; i < IO_LEN; i++) {
    out_neurons[i] = WalrusCtxt(scheme_type::bgv);
    for (int j = 0; j < NUM_HIDDEN_NEURONS; j++) {
      WalrusCtxt tmp = WalrusCtxt(scheme_type::bgv);
      WalrusMultPlain(tmp, hidden_neurons[j], cloud_weights[1][i*NUM_HIDDEN_NEURONS+j]);
      WalrusAdd(out_neurons[i], out_neurons[i], tmp);
    }
  }
  return WalrusParameterize(out_neurons);
}

vector<WalrusCtxt> cloud_second_pass(Encryptor& encryptor, Evaluator& evaluator, RelinKeys& relin_keys, vector<WalrusCtxt>& input_ct) {
  vector<WalrusCtxt> hidden_neurons(NUM_HIDDEN_NEURONS);
  vector<WalrusCtxt> out_neurons(IO_LEN);

  // First Fully-Connected Layer 
  for (int i = 0; i < NUM_HIDDEN_NEURONS; i++) {
    hidden_neurons[i] = WalrusCtxt(scheme_type::bgv);
    encryptor.encrypt_zero(hidden_neurons[i].ctxt);
    for (int j = 0; j < IO_LEN; j++) {
      WalrusCtxt tmp = WalrusCtxt(scheme_type::bgv);
      tmp.WalrusEncryptSingle(encryptor, 0);
      WalrusMultPlain(tmp, input_ct[j], cloud_weights[0][i*IO_LEN+j], evaluator);
      WalrusAdd(hidden_neurons[i], hidden_neurons[i], tmp, evaluator);
    }
  }

  // Activation Function (x^2)
  for (int i = 0; i < NUM_HIDDEN_NEURONS; i++) {
    WalrusMult(hidden_neurons[i], hidden_neurons[i], hidden_neurons[i], evaluator, relin_keys);
  }

  // Second Fully-Connected Layer
  for (int i = 0; i < IO_LEN; i++) {
    out_neurons[i] = WalrusCtxt(scheme_type::bgv);
    out_neurons[i].WalrusEncryptSingle(encryptor, 0);
    evaluator.mod_switch_to_next_inplace(out_neurons[i].ctxt);
    evaluator.mod_switch_to_next_inplace(out_neurons[i].ctxt);
    for (int j = 0; j < NUM_HIDDEN_NEURONS; j++) {
      WalrusCtxt tmp = WalrusCtxt(scheme_type::bgv);
      tmp.WalrusEncryptSingle(encryptor, 0);
      WalrusMultPlain(tmp, hidden_neurons[j], cloud_weights[1][i*NUM_HIDDEN_NEURONS+j], evaluator);
      evaluator.mod_switch_to_next_inplace(tmp.ctxt);
      WalrusAdd(out_neurons[i], out_neurons[i], tmp, evaluator);
    }
  }
  return out_neurons;
}

void client() {
  // Create ciphertext objects for parameterization
  vector<WalrusCtxt> inputs(IO_LEN);
  for (size_t i = 0; i < IO_LEN; i++) {
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

  // Create generator for non-zero random 8-bit numbers for inputs
  random_device rd;
  mt19937 gen(rd());
  uniform_int_distribution<uint64_t> distribution(1, 255);

  // Encrypt batched inputs 
  size_t slot_count = batch_encoder.slot_count();
  for (size_t i = 0; i < IO_LEN; i++) {
    vector<uint64_t> in_vec(slot_count);
    for (size_t j = 0; j < slot_count; j++) {
      in_vec[j] = distribution(gen);
    }
    inputs[i].WalrusEncryptVector(batch_encoder, encryptor, in_vec);
  }

  // Run encrypted inference on the cloud
  high_resolution_clock::time_point t1 = high_resolution_clock::now();
  vector<WalrusCtxt> enc_res = cloud_second_pass(encryptor, evaluator, relin_keys, inputs);
  high_resolution_clock::time_point t2 = high_resolution_clock::now();
  duration<double> time_span = duration_cast<duration<double>>(t2 - t1);
  std::cout << "Inference Latency: " << time_span.count() << " seconds" << endl;;
  std::cout << "Amortized Latency: " << time_span.count() / slot_count << " seconds" << endl;

  return;
}

int main() {
  cloud_generate_weights();
  client();
  return 0;
}