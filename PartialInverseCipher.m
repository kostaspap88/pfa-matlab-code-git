% Invert the ciphertext to the penultimate AES round
function [intermediate3] = PartialInverseCipher(last_round_key, ciphertext, inv_sbox)

ct = reshape(ciphertext, [4 4]);
% careful with the selection of ciphertext bytes in order to account for
% the shift rows
% addroundkey 
intermediate1 = bitxor([ct(1,1) ct(2,4) ct(3,3) ct(4,2)], last_round_key);

% inverse sbox
intermediate2 = zeros(1,4);
for i=1:4
    intermediate2(i) = inv_sbox(intermediate1(i) + 1);
end

% inverse mixcolumns for a single byte result
intermediate3(1)=bitxor(bitxor(bitxor(xtime(intermediate2(1),14),xtime(intermediate2(2),11)),xtime(intermediate2(3),13)),xtime(intermediate2(4),9));

end