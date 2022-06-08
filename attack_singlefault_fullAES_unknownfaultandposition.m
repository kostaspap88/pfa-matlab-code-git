% PFA with unknown fault and position on the full AES
function [key] = attack_singlefault_fullAES_unknownfaultandposition(ciphertext, vsize, sboxc, plaintext)
% Note that sboxc.faulty is only used to compute the
% AES for the verification step i.e. the fault value and position are not
% recovered from it

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

% 2. continue with the MLE attack for every byte
key_candidate = zeros(16, vsize);
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
    % we enumerate over all positions
    
    for fault_position=0:vsize-1
        v = sboxc.sbox(fault_position + 1);
        v_faulty = bitxor(v, fault_estimated);
        key_candidate(index, fault_position + 1) = bitxor(cmax(max_cmax_index), v_faulty);
    end

end

% 4. We have the ciphertext 
% Option 1: We also need a correct plaintext to verify the
% candidate. Note that we only need a single correct plaintext-ciphtertext pair
correct_plaintext = plaintext(1,:);
correct_ciphertext = ciphertext(1,:);

key.mle_steps_unknownfault_unknownposition_ptctpair = [NaN NaN NaN NaN NaN NaN NaN NaN NaN NaN NaN NaN NaN NaN NaN NaN];
for i=1:vsize
   % the current candidate is the round10 candidate
   current_candidate = key_candidate(:,i);
   % we need to convert it to the AES key and then use it in verification
   aes_key = ReverseKeyExpansion(current_candidate, sboxc);
   verification = Cipher(aes_key, correct_plaintext, sboxc.sbox, sboxc.sbox_faulty)' == correct_ciphertext;
   if sum(verification) == 16
       key.mle_steps_unknownfault_unknownposition_ptctpair = current_candidate';
   end

end

% Option 2: if we have no access to a correct plaintext-ciphtertext pair we
% can just encrypt until we compute the 9th round sbox output and check 
% that its distribution is missing values

% NOTES: there is something strange in this scenario. It is not clear
% whether it must be done with decryption or with encryption and in the
% case of decryption it is not clear if the inverse sbox is faulted (like
% the forward sbox) or not. It is also not clear what is the role of
% mixcolumns.
% Finally the work states to get the 'output of subbytes in the penultimate
% round' but all such outputs maintain the bias
% The implemented attack is still included for reference

% candidate_list = [];
% % penultimate_round_sboxout = zeros(size(ciphertext,1), 16);
% penultimate_round_sboxout = zeros(300, 16);
% 
% for i=1:vsize
%     
%     current_aes_key = ReverseKeyExpansion(key_candidate(:,i), sboxc);
%     % instead of the value we can also set it to the full no_traces i.e. 
%     % the paper recommends approx. 300
%     for counter=1:size(ciphertext,1)
%          [pt] = InvCipher(current_aes_key, plaintext(counter,:), sboxc.inv_sbox, sboxc.inv_sbox_faulty);
%          penultimate_round_sboxout(counter,:) = rp_sboxout;
%     end
%     
%     pr_frequency = histcounts(penultimate_round_sboxout, vsize);
%     no_zeros = sum(pr_frequency == 0);
%     if no_zeros > 0
%        candidate_list =  [candidate_list; key_candidate(:,i)']; 
%     end
% 
% end
% 
% key.mle_steps_unknownfault_unknownposition_penultimate = candidate_list;


end

