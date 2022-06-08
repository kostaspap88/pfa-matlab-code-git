% PFA with unknown fault value on the last round of a single sbox AES
function [key] = attack_singlefault_singlesboxAES_unknownfault(ciphertext, vsize, sboxc, faultc)

% 1. Recovering the unknown fault value
% First use any available ciphertext to recover it
% and we continue with e.g. an MLE-based PFA attack
% in the single byte case, we use all the available traces to estimate the
% fault
frequency = histcounts(ciphertext, 256);
% find the least frequent value of the ciphertext (lfc)
[lfc_value, lfc] = min(frequency);
lfc = lfc - 1;
% find the most frequent value of the ciphertext (mfc)
[mfc_value, mfc] = max(frequency);
mfc = mfc - 1;
% their difference equals the fault
fault_estimated = bitxor(lfc, mfc);
 
% 2. continue with the mle attack
values = 0:vsize-1;
impossible_ciphertext = [];
for i=1:length(values)   
    if (frequency(values(i) + 1) > 0)
        impossible_ciphertext = [impossible_ciphertext, values(i)];
    end
end
cmin = setdiff(values, impossible_ciphertext);

for i=1:length(cmin)
    cmax(i) = bitxor(cmin(i), fault_estimated);
end
[max_cmax, max_cmax_index] = max(frequency(cmax + 1));

% 3. compute the key
% we assume that we know the original position
v = sboxc.sbox(faultc.fault_single_position + 1);
v_faulty = bitxor(v, fault_estimated);
key.mle_steps_unknownfault = bitxor(cmax(max_cmax_index), v_faulty);


end