#include "parameterizer.hpp"

using namespace std;
using namespace seal;

EncryptionParameters WalrusParameterize(vector<WalrusCtxt>& outputs, 
                                        int desired_slots) {
  if (outputs.size() < 1) {
    cout << "No output ciphertexts provided!" << endl;
  }

  int max_mult_depth = -1;
  int max_add_depth = -1;
  EncryptionParameters output_parms(outputs[0].scheme);
  for (size_t i = 0; i < outputs.size(); i++) {
    if (outputs[i].mult_depth > max_mult_depth) {
      max_mult_depth = outputs[i].mult_depth;
    }
    if (outputs[i].add_depth > max_add_depth) {
      max_add_depth = outputs[i].add_depth;
    }
  }
  if (outputs[0].scheme == scheme_type::bgv) {
    size_t poly_modulus_degree = 0;
    if ((max_mult_depth < 2 && max_add_depth < 45) && desired_slots < 2049) {
      poly_modulus_degree = 4096;
    }
    else if ((max_mult_depth < 4 && max_add_depth < 147) && desired_slots < 4097) {
      poly_modulus_degree = 8192;
    }
    else if ((max_mult_depth < 8 && max_add_depth < 361) && desired_slots < 8193) {
      poly_modulus_degree = 16384;
    }
    else if ((max_mult_depth < 15 && max_add_depth < 797) && desired_slots < 16385) {
      poly_modulus_degree = 32768;
    }
    else {
      cout << "SEAL doesn't support parameters that fulfill the requirements of the application!" << endl;
      exit(0);
    }
    output_parms.set_poly_modulus_degree(poly_modulus_degree);
    output_parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    output_parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));
  }
  return output_parms;
}