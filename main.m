% Persistent Fault Analysis (PFA) on AES
% Author: Kostas Papagiannopoulos -- kostaspap88@gmail.com -- kpcrypto.net
% Paper Sources: 
% 1. Persistent fault analysis on block ciphers, Zhang et al.
% 2. Persistent fault analysis in practice, Zhang et al.
% 3. Persistent fault analysis with few encryptions, Carre et al.
% 4. SPFA: SFA on Multiple Persistent Faults, Engels et al.
% 5. Ciphertext-only Fault Analysis on the LED Lightweight Cryptosystem in 
% the Internet of Things Li et al.

clear all;
close all;

% configure the attack
[no_attacks, no_traces_vector, vsize, keyc, sboxc, faultc] = config();
len_vec = length(no_traces_vector);

% initialize the PFA attack results
pfa_result = initialize_result(len_vec, no_attacks);


implementation_choice = 1;
attack_choice = 1;


% repeat the attack while trying a different number of faulted ciphertexts
for k=1:len_vec 
    
    no_traces = no_traces_vector(k);

    % repeat an attack with 'no_traces' multiple times using random faulted
    % ciphtertexts
    for j=1:no_attacks 
        
        switch implementation_choice
            
            case 1    
                % 10th round AES single sbox implementation 
                [sboxinput_singlesbox, sboxoutput_singlesbox, ciphertext_singlesbox] = implementation_singlesbox_lastroundAES(keyc.key_byte_lastroundAES_correct, no_traces, sboxc, vsize);
            
            case 2
                % duplicated comparison on 10th round AES single sbox implementation
                [ciphertext_singlesbox_duplication] = implementation_singlesbox_lastroundAES_duplication(keyc.key_byte_lastroundAES_correct, no_traces, sboxc, vsize);
            
            case 3
                % full AES implementation 
                [plaintext_full, ciphertext_full, other_output] = implementation_fullAES(keyc.key_fullAES_correct, no_traces, sboxc);
        
        end
        
        
        
        switch attack_choice

            case 1
                % attack on the single-sbox round10 implementation using the 3 attack strategies from 'PFA on block ciphers'
                result.key_singlesbox(k,j) = attack_singlefault_singlesboxAES(ciphertext_singlesbox.singlefault, vsize, sboxc, faultc);
                % compare the result with keyc.key_byte_lastroundAES_correct
        
            case 2
                % attack on the full AES implementation using the 3 attack strategies from 'PFA on block ciphers'
                result.key_full(k,j) = attack_singlefault_fullAES(ciphertext_full.singlefault, vsize, sboxc, faultc); 
                % compare the result with keyc.key_lastroundAES_correct
              
            case 3
                % MLE attack on the single-sbox round10 implementation using the 2-step approach from 'PFA with few encryptions'
                result.key_singlesbox_mle(k,j) = attack_singlefault_singlesboxAES_mle(ciphertext_singlesbox.singlefault, vsize, sboxc, faultc);
                % compare the result with keyc.key_byte_lastroundAES_correct
               
            case 4
                % MLE attack on the full AES implementation using the 2-step approach from 'PFA with few encryptions'
                result.key_fullAES_mle(k,j) = attack_singlefault_fullAES_mle(ciphertext_full.singlefault, vsize, sboxc, faultc);
                % compare the result with keyc.key_lastroundAES_correct

            case 5
                % MLE attack on the single-sbox round10 implementation when the fault is unknown from 'PFA in practice'
                result.key_singlesbox_unknownfault(k,j) = attack_singlefault_singlesboxAES_unknownfault(ciphertext_singlesbox.singlefault, vsize, sboxc, faultc);
                % compare the result with keyc.key_byte_lastroundAES_correct
               
            case 6
                % MLE attack on the full AES implementation when the fault is unknown from 'PFA in practice'
                result.key_fullAES_unknownfault(k,j) = attack_singlefault_fullAES_unknownfault(ciphertext_full.singlefault, vsize, sboxc, faultc);
                % compare the result with keyc.key_lastroundAES_correct
                
            case 7 
                % MLE attack on the single-sbox round10 implementation when both the fault and position are unknown from 'PFA in practice'
                result.key_singlesbox_unknownfaultandposition(k,j) = attack_singlefault_singlesboxAES_unknownfaultandposition(ciphertext_singlesbox.singlefault, vsize, sboxc, sboxinput_singlesbox(1) );
                % compare the result with keyc.key_byte_lastroundAES_correct
                
            case 8 
                % MLE attack on the full AES implementation when both the fault and position are unknown from 'PFA in practice'
                result.key_fullAES_unknownfaultandposition(k,j) = attack_singlefault_fullAES_unknownfaultandposition(ciphertext_full.singlefault, vsize, sboxc, plaintext_full(1,:) );
                % compare the result with keyc.key_lastroundAES_correct
                
            case 9
                % Statistical persistent fault analysis from 'SPFA: SFA on Multiple Persistent Faults' recovering a byte
                result.key_singlebyte_spfa = attack_singlefault_fullAES_spfa(ciphertext_full.singlefault, vsize, sboxc, keyc.key_fullAES_correct);
                % compare the result with keyc.key_lastroundAES_correct(1)
                
            case 10
                % attack on the duplication-protected single-sbox round10 implementation using the 3 attack strategies from 'PFA on block ciphers'
                % notice how strategy 3 will always fail because of fault detection
                result.key_singlesbox_duplication_nco(k,j) = attack_singlefault_singlesboxAES(ciphertext_singlesbox_duplication.nco, vsize, sboxc, faultc);
                result.key_singlesbox_duplication_rco(k,j) = attack_singlefault_singlesboxAES(ciphertext_singlesbox_duplication.rco, vsize, sboxc, faultc);
                result.key_singlesbox_duplication_vco(k,j) = attack_singlefault_singlesboxAES(ciphertext_singlesbox_duplication.zvo, vsize, sboxc, faultc);
                % compare the result with keyc.key_byte_lastroundAES_correct
        
        end
    
    end

end






