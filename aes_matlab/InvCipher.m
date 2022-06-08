function [Out, PRSboxOut] = InvCipher(key,In,Sbox,SboxFaulty)
%AES-128,192,or 256 inverse cipher
%Impliments FIBS-197, key is 128, 192, or 256-bit hexidecimal input, 
%message (In) is 128-bit hexidecimal. Application does not check lengths of
%keys or message input but will error if they are not of the correct
%length.
%David Hill
%Version 1.0.4
%1-25-2021

Nk=2*length(key)/8; % adjusted for nibbbles/bytes

% In=hex2dec(reshape(In,2,[])');

w=KeyExpansion(key,Nk,Sbox,SboxFaulty);
state=reshape(In,4,[]);
state=AddRoundKey(state,w(:,4*(Nk+6)+1:4*(Nk+7)));
for k=(Nk+6):-1:2
    state=InvShiftRows(state);
    
    if (k==9)
        PRSboxOut = reshape(state,1,16);
    end
    
    state=InvSubBytes(state,SboxFaulty);
    
    

    
    state=AddRoundKey(state,w(:,4*(k-1)+1:4*k));
    state=InvMixColumns(state);
end
state=InvShiftRows(state);
state=InvSubBytes(state,SboxFaulty);
state=AddRoundKey(state,w(:,1:4));
Out=state(:)';
% Out=lower(dec2hex(Out(1:length(In)))');
% Out=Out(:)';
end