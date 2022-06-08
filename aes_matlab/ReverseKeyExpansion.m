% Compute the AES key from the last round key
function key = ReverseKeyExpansion(lastround_key,sboxc)

Nk = 4;
Sbox=sboxc.sbox;

lrk=reshape(lastround_key,4,[]);
ww = zeros(4, 44);
ww(:,41:44) = lrk;

for j=39:-1:0
    temp=ww(:,j+3+1);
    if mod(j,Nk)==0
        temp=SubBytes(circshift(temp,-1),Sbox); % is that the case for PFA? Does it affect the key schedule or it it precomputed?
        n=1;
        m=0;
        while m<(j+4)/Nk-1%needed to modulate higher powers of 2 per standard
            n=xtime(2,n);
            m=m+1;
        end
        temp=bitxor(temp,[n,0,0,0]');
    elseif Nk>6 && mod(j,8)==4
        temp=SubBytes(temp,Sbox);% is that the case for PFA? Does it affect the key schedule or it it precomputed?
    end
    ww(:,j+1)=bitxor(ww(:,j+4+1),temp);
end

key = reshape(ww(:,1:4),1,16);

end
