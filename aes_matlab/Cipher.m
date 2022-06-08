function [Out, OtherOut] = Cipher(key, In, Sbox_for_keyschedule, Sbox_for_round)

%AES-128,192,256 cipher
%Implements FIBS-197, key is a 128, 292, or 256-bit hexidecimal input, 
%message (In) is 128-bit hexidecimal. Application does not check lengths of
%keys or message input but will error if they are not of the correct
%length.
%David Hill
%Version 1.0.4
%1-25-2021

% we reserve the OtherOut for any other intermediate of AES that we
% want to fetch for debugging/distribution check purposes
OtherOut = [];

Nk=2*length(key)/8; % adjusted for nibbbles/bytes

% note that the key schedule may use a different sbox than the AES round
% e.g. often the key schedule sbox is correct and was used during key
% precomputations while the AES round could use the faulty sbox
w=KeyExpansion(key,Nk,Sbox_for_keyschedule);%key expansion per standard

state=reshape(In,4,[]);%reshapes input into state matrix

state=AddRoundKey(state,w(:,1:4));%conducts first round

for k=2:(Nk+6)%conducts follow-on rounds
    
    state=SubBytes(state,Sbox_for_round); % notice the usage of a different sbox here
 
    state=ShiftRows(state);
   
    state=MixColumns(state);    
    
    state=AddRoundKey(state,w(:,4*(k-1)+1:4*k));
end

state=SubBytes(state,Sbox_for_round);

state=ShiftRows(state);

state=AddRoundKey(state,w(:,4*(Nk+6)+1:4*(Nk+7)));

Out=state(:);%changes output to column vector

end

% code used for hex debugging
% Out=lower(dec2hex(Out(1:length(In)))');%converts output to hex
% Out=Out(:)';%converts output to row vector