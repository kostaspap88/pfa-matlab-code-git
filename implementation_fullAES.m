% Implementation the full AES cipher using various sboxes that have been
% faulted with PFA
function [plaintext, ciphertext] = implementation_fullAES(key, no_traces, sboxc)


% use the AES matlab implementation included
addpath('./aes_matlab/');

% generate the AES plaintext
plaintext = randi(256, no_traces, 16) - 1;

% compute the full AES
% inputs: the full AES key, the plaintext, the correct sbox and the faulty
% sbox
% outputs: ciphertext and 'other_output' used for debugging any
% intermediate value needed

cipher = zeros(no_traces, 16);

% if needed:
% other_output1 = zeros(no_traces, 16);
% other_output2 = zeros(no_traces, 16);
% other_output3 = zeros(no_traces, 16);

for i=1:no_traces
    
    % the standard AES encryption
    [ct, otherout1, otherout2, otherout3] = Cipher(key, plaintext(i,:), sboxc.sbox, sboxc.sbox_faulty);
    
    cipher(i,:) = ct;
    
    % if needed:
    % other_output1(i,:) = reshape(otherout1,1,16);
    % other_output2(i,:) = reshape(otherout2,1,16);
    % other_output3(i,:) = reshape(otherout3,1,16);
    
end

ciphertext.singlefault = cipher;

% if needed:
% ciphertext.otherout1 = other_output1;
% ciphertext.otherout2 = other_output2;
% ciphertext.otherout3 = other_output3;

end

% code used for testing hex values -- can be ignored
% plaintext=hex2dec(reshape('11823665AEF721F37752A1BE9DBD5A0E',2,[])')';
% backto_plaintext=lower(dec2hex(plaintext(1,1:16))');%converts output to hex
% backto_plaintext=backto_plaintext(:)';
% [ct] = Cipher(key, zeros(1,16), sboxc.sbox, sboxc.sbox_faulty);
% Out = lower(dec2hex(ciphertext(1,1:16))'); %converts output to hex
% Out = Out(:)'; %converts output to row vector