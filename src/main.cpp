#include <seal/seal.h>
#include <fstream>
#include <iostream>

using namespace std;
using namespace seal;

void run_BFV_scheme() {
  chrono::high_resolution_clock::time_point time_start, time_end;
  EncryptionParameters parms(scheme_type::bfv);

  size_t poly_mod_degrees = 4096;

  parms.set_poly_modulus_degree(poly_mod_degrees);
  parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_mod_degrees));
  parms.set_plain_modulus(786433);

  auto &plain_modulus = parms.plain_modulus();

  cout << "Generating secret/public keys: ";
  KeyGenerator keygen(parms);
  cout << "Done" << endl;

  auto secret_key = keygen.secret_key();
  PublicKey pub_key;
  keygen.create_public_key(pub_key);

  Encryptor encryptor(parms, pub_key);
  Decryptor decryptor(parms, secret_key);
  BatchEncoder batch_encoder(parms);

  chrono::microseconds time_encrypt_sum(0);
  chrono::microseconds time_decrypt_sum(0);

  Plaintext plain(poly_mod_degrees, 0);
  Plaintext plain2(poly_mod_degrees, 0);
  
  size_t slot_count = batch_encoder.slot_count();
  vector<uint64_t> pod_vector;
  random_device rd;
  for (size_t i = 0; i < slot_count; i++)
  {
      pod_vector.push_back(plain_modulus.reduce(rd()));
  }
  batch_encoder.encode(pod_vector, plain);

  Ciphertext ciphertext(parms);
  time_start = chrono::high_resolution_clock::now();
  encryptor.encrypt(plain, ciphertext);
  time_end = chrono::high_resolution_clock::now();
  time_encrypt_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);

  cout << "BFV Encryption Time: " << endl;
  cout << time_encrypt_sum.count() <<  "ms" << endl;

  time_start = chrono::high_resolution_clock::now();
  decryptor.decrypt(ciphertext, plain2);
  time_end = chrono::high_resolution_clock::now();
  time_decrypt_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);

  cout << "BFV Decryption Time: " << endl;
  cout << time_decrypt_sum.count() << "ms" << endl;

  ofstream pt;
  pt.open("bfv_pt", ios::binary);
  plain.save(pt);

  ofstream ct;
  ct.open("bfv_ct", ios::binary);
  ciphertext.save(ct);
}

void run_CKKS_scheme() {
  chrono::high_resolution_clock::time_point time_start, time_end;
  EncryptionParameters parms(scheme_type::ckks);
  size_t poly_mod_degrees = 4096;
  parms.set_poly_modulus_degree(poly_mod_degrees);
  parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_mod_degrees));


  cout << "Generating secret/public keys: ";
  KeyGenerator keygen(parms);
  cout << "Done" << endl;

  auto secret_key = keygen.secret_key();
  PublicKey pub_key;
  keygen.create_public_key(pub_key);

  Encryptor encryptor(parms, pub_key);
  Decryptor decryptor(parms, secret_key);
  CKKSEncoder ckks_encoder(parms);

  chrono::microseconds time_encrypt_sum(0);
  chrono::microseconds time_decrypt_sum(0);

  Plaintext plain(parms.poly_modulus_degree() * parms.coeff_modulus().size(), 0);
  Plaintext plain2(poly_mod_degrees, 0);

  vector<double> pod_vector;
  random_device rd;
  for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
  {
      pod_vector.push_back(1.001 * static_cast<double>(i));
  }
  
  double scale = sqrt(static_cast<double>(parms.coeff_modulus().back().value()));
  ckks_encoder.encode(pod_vector, scale, plain);

  Ciphertext ciphertext(parms);
  time_start = chrono::high_resolution_clock::now();
  encryptor.encrypt(plain, ciphertext);
  time_end = chrono::high_resolution_clock::now();
  time_encrypt_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);

  cout << "CKKS Encryption Time: " << endl;
  cout << time_encrypt_sum.count() <<  "ms" << endl;

  time_start = chrono::high_resolution_clock::now();
  decryptor.decrypt(ciphertext, plain2);
  time_end = chrono::high_resolution_clock::now();
  time_decrypt_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);

  cout << "CKKS Decryption Time: " << endl;
  cout << time_decrypt_sum.count() << "ms" << endl;

  ofstream pt;
  pt.open("ckks_pt", ios::binary);
  plain.save(pt);

  ofstream ct;
  ct.open("ckks_ct", ios::binary);
  ciphertext.save(ct);
}

void run_BGV_scheme() {
  chrono::high_resolution_clock::time_point time_start, time_end;
  EncryptionParameters parms(scheme_type::bgv);
  size_t poly_mod_degrees = 4096;
  parms.set_poly_modulus_degree(poly_mod_degrees);
  parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_mod_degrees));
  parms.set_plain_modulus(786433);
  auto &plain_modulus = parms.plain_modulus();

  cout << "Generating secret/public keys: ";
  KeyGenerator keygen(parms);
  cout << "Done" << endl;

  auto secret_key = keygen.secret_key();
  PublicKey pub_key;
  keygen.create_public_key(pub_key);

  Encryptor encryptor(parms, pub_key);
  Decryptor decryptor(parms, secret_key);
  BatchEncoder batch_encoder(parms);

  chrono::microseconds time_encrypt_sum(0);
  chrono::microseconds time_decrypt_sum(0);

  Plaintext plain(poly_mod_degrees, 0);
  Plaintext plain2(poly_mod_degrees, 0);

  size_t slot_count = batch_encoder.slot_count();
  vector<uint64_t> pod_vector;
  random_device rd;
  for (size_t i = 0; i < slot_count; i++)
  {
      pod_vector.push_back(plain_modulus.reduce(rd()));
  }
  
  batch_encoder.encode(pod_vector, plain);

  Ciphertext ciphertext(parms);
  time_start = chrono::high_resolution_clock::now();
  encryptor.encrypt(plain, ciphertext);
  time_end = chrono::high_resolution_clock::now();
  time_encrypt_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);

  cout << "BGV Encryption Time: " << endl;
  cout << time_encrypt_sum.count() <<  "ms" << endl;

  time_start = chrono::high_resolution_clock::now();
  decryptor.decrypt(ciphertext, plain2);
  time_end = chrono::high_resolution_clock::now();
  time_decrypt_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);

  cout << "BGV Decryption Time: " << endl;
  cout << time_decrypt_sum.count() << "ms" << endl;

  ofstream pt;
  pt.open("bgv_pt", ios::binary);
  plain.save(pt);

  ofstream ct;
  ct.open("bgv_ct", ios::binary);
  ciphertext.save(ct);
}

int main(){
  run_BFV_scheme();
  run_CKKS_scheme();
  run_BGV_scheme();
}
