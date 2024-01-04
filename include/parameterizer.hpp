#include "seal/seal.h"
#include "ctxt.hpp"

seal::EncryptionParameters WalrusParameterize(std::vector<WalrusCtxt>& outputs, 
                                              int desired_slots=0);