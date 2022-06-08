% PFA with maximum likelihood estimation on the last round of AES
function [key] = attack_singlefault_singlesboxAES_mle(ciphertext, vsize, sboxc, faultc)

% we assume that we know the fault position and the fault value
v_faulty = sboxc.sbox_faulty(faultc.fault_single_position + 1);
v = sboxc.sbox(faultc.fault_single_position + 1);
fault = bitxor(v, v_faulty);

% Steps 1-4 is the step-based approach MLE approach of Carre et al.
% It results in the top key candidates
% The process is similar to PFA in practice by Zhang et al.

% 1. first count the appearances of the values
frequency = histcounts(ciphertext, 256);

% 2. remove all the values that appear at least once (like in strategy 2 of PFA in block ciphers)
values = 0:vsize-1;
impossible_ciphertext = [];
for i=1:length(values)   
    if (frequency(values(i) + 1) > 0)
        impossible_ciphertext = [impossible_ciphertext, values(i)];
    end
end
cmin = setdiff(values, impossible_ciphertext);

% 3. for all the remaining values (cmin) compute the correspoding
% cmax (the part from strategy 3)
for i=1:length(cmin)
    cmax(i) = bitxor(cmin(i), fault);
end

% 4. lookup the frequency of all cmax and find the maximum among them
[max_cmax, max_cmax_index] = max(frequency(cmax + 1));
% finally, compute the key
key.mle_steps = bitxor(cmax(max_cmax_index), v_faulty);

% Carre et al. also put forward a full probability approach that is
% equivalent but outputs a probability score instead of the candidates
% directly 
values = 0:vsize-1;
probability_product = zeros(length(values), 1);
log_probability_product = zeros(length(values), 1);
no_traces = size(ciphertext,1);
for i=1:length(values)  % for all key candidates
    index_v = bitxor(ciphertext, values(i)) == v;
    index_v_faulty = bitxor(ciphertext, values(i)) == v_faulty;
    mk0 = sum(index_v);
    mk2 = sum(index_v_faulty);
    mk1 = no_traces - mk0 - mk2;
    % Note that mk2 + mk1 + mk0 == no_traces
    
    % compute the probability product -- numerically unstable due to
    % exponentiations
    % if mk0 > 0
    %     probability_product(i) = 0;    
    % else
    %     probability_product(i) = (1/(vsize-1))^mk1 * (2/(vsize-1))^mk2;  
    % end    
    
    % take the log(probability product) -- numerically stable
    if mk0 > 0
        log_probability_product(i) = -Inf;    
    else
        log_probability_product(i) = mk1 * log(1/(vsize-1)) + mk2 * log(2/(vsize-1)); 
    end
    
end

% [max_prob_val, max_index_prob] = max(probability_product);
% key.mle_probability = max_index_prob - 1;

[max_logprob_val, max_index_logprob] = max(log_probability_product);
key.mle_log_probability = max_index_logprob - 1;

end