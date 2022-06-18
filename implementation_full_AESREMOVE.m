% Implementation the full AES cipher using various sboxes that have been
% faulted with PFA
function [plaintext, ciphertext, other_output] = implementation_full_AES(key, no_traces, sboxc, extra_MC)


% use AES matlab implementation included
addpath('./aes_matlab/');

% generate the AES plaintext
plaintext = randi(256, no_traces, 16) - 1;

% compute the full AES
% inputs: the full AES key, the plaintext, the correct sbox and the sbox
% after PFA has injected faults in it
ciphertext = zeros(no_traces, 16);
other_output = zeros(no_traces, 16);

% just for testing hex values --
% plaintext=hex2dec(reshape('11823665AEF721F37752A1BE9DBD5A0E',2,[])')';
% backto_plaintext=lower(dec2hex(plaintext(1,1:16))');%converts output to hex
% backto_plaintext=backto_plaintext(:)';
% [ct] = Cipher(key, zeros(1,16), sboxc.sbox, sboxc.sbox_faulty);

for i=1:no_traces
    % this is the standard AES encryption
    [ct, otherout] = Cipher(key, plaintext(i,:), sboxc.sbox, sboxc.sbox_faulty, extra_MC);
    % you can also choose to use a modified AES that uses invMC instead of
    % MC during every round 
    % [ct, otherout] = Cipher_withinvMC(key, plaintext(i,:), sboxc.sbox, sboxc.sbox_faulty,extra_MC);
    ciphertext(i,:) = ct;
    other_output(i,:) = otherout;
 end

% just for testing hexvalues --
% Out = lower(dec2hex(ciphertext(1,1:16))'); %converts output to hex
% Out = Out(:)'; %converts output to row vector


end