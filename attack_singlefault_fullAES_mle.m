% PFA with unknown fault value on full AES
function [key] = attack_singlefault_fullAES_mle(ciphertext, vsize, sboxc, faultc)


% 1. Recovering the unknown fault value
% First use any available ciphertext to recover it
% and we continue with e.g. an MLE-based PFA attack
% Note that we can use all ciphertext bytes towards estimating the fault

score = zeros(vsize,1);
for theta = 0:vsize-1
    
    current_logproduct = 0;
    
    for j=0:15

        frequency = histcounts(ciphertext(:,j+1), vsize);

        current_sum = 0;
        for l=0:vsize-1
            
            nj_l = frequency(l+1);
            nj_lxortheta = frequency(bitxor(l, theta) + 1);
            
            if (nj_l > 0)
                delta = 0;
            elseif (nj_l == 0)
                delta = 1;
            end

            current_sum = current_sum + delta * 2^nj_lxortheta;
        end
        
        % use log of product for numerical stability
        current_logproduct = current_logproduct + log(current_sum);
     
    end
    score(theta+1) = current_logproduct;
    
end
[max_val, max_index] = max(score);
fault_estimated = max_index - 1;
% Note that estimating the fault (since it uses all ciphertext values)
% takes less than extracting the key in the full AES case

% 2. continue with the mle attack for every byte
for index=1:16
    
    frequency = histcounts(ciphertext(:,index), vsize);

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
    key.mle_steps_unknownfault(index) = bitxor(cmax(max_cmax_index), v_faulty);
end

end