% Statistical Persistent Fault Attack
% Note that this attack does not need the fault or fault position
% Note that we pass the full AES key which is unknown to the adversary
% We do that to fix 3 key bytes in order to speed up the process which 
% would otherwise have complexity 2^32
function [key] = attack_singlefault_fullAES_spfa(ciphertext, vsize, sboxc, full_aes_key)

% In the standard AES case we target the last round key
% See the process used by: A Fault Attack on the LED Block Cipher, Li et
% al. pages 4 and 5

Nk=2*length(full_aes_key)/8;
w = KeyExpansion(full_aes_key,Nk,sboxc.sbox);
last_round_key_correct = w(:,41:44);

fixed_key_part = [last_round_key_correct(2,4) last_round_key_correct(3,3) last_round_key_correct(4,2)];



% score = zeros(vsize,1);
intermediate = zeros(size(ciphertext, 1),1);
for key_guess=0:vsize-1
    key_guess
    last_round_key_guess = [key_guess fixed_key_part];
    % invert the cipher starting from the faulty ciphertexts, using the
    % current key guess and the correct AES sbox
    for i=1:size(ciphertext,1)
                
        % SPFA vs. standard AES implementation
        intermediate(i) = PartialInverseCipher(last_round_key_guess, ciphertext(i,:), sboxc.inv_sbox);

    end
  
    score(key_guess+1) = squared_euclidian_imbalance(intermediate, vsize);
    
end

[maxval, maxindex] = max(score);
key = maxindex - 1;
% after recover the first key piece (4 bytes), the adversary can proceed to recover the other
% three 4-byte key pieces. Then they can apply MC(SR(whole_key_state))

end