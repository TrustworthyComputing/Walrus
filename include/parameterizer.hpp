#include "seal/seal.h"
#include "ctxt.hpp"

seal::EncryptionParameters WalrusParameterize(vector<WalrusCtxt>& outputs, 
                                              int desired_slots, 
                                              seal::scheme_type scheme);