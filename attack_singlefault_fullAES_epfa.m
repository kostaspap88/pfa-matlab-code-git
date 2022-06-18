% Enhanced PFA attack
% for the reference AES key [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15] we have
% that:
% K10 = [19 17 29 127 227 148 74 23 243 7 167 139 77 43 48 197] and
% K9 = [84,153,50,209,240,133,87,104,16,147,237,156,190,44,151,78]

% Try this attack with 2k traces. This would result in more than one
% candidates for K10 after the 10th round PFA
% Still the number of K10 candidates is not too big to make EPFA too hard
% Continuing with the round 9 constraints will reduce the K10 candidate
% list

function [K10_sieved_candidates] = attack_singlefault_fullAES_epfa(ciphertext, vsize, sboxc, faultc)


% use allcomb function to compute the Cartesian product
addpath('./allcomb/');

% faulty value
v_faulty = sboxc.sbox_faulty(faultc.fault_single_position+1);

% unfaulted value (impossible value)
v_correct = sboxc.sbox(faultc.fault_single_position+1);

% Repeat Algorithm 1 for 16 key bytes
for state_index=1:16
    
    % initially all key candidates are possible
    key_guesses = 0:vsize-1;
    
    % exclude key candidates 
    for j=1:size(ciphertext,1)
        check_value = bitxor(ciphertext(j,state_index), v_correct);
        if ismember(check_value, key_guesses)
            key_guesses = setdiff(key_guesses, check_value);
        end
    end
    
    % store the remaining key guesses for every key byte
    D{state_index} = key_guesses;
    
end

% expand D to all possible K10 keys using the allcomb() function
K10_candidates = allcomb(D{1}, D{2}, D{3}, D{4}, D{5}, D{6}, D{7}, D{8}, D{9}, D{10}, D{11}, D{12}, D{13}, D{14}, D{15}, D{16}); 

% count the K10 roundkeys that pass the PFA checks of round 9
counter = 1; 

% list of 'sieved' candidates
K10_sieved_candidates = [];

% try all K10 candidates
for i=1:size(K10_candidates,1)
    
    % select a K10
    K10 = K10_candidates(i,:);
    
    % Compute the 9th round key K9 from K10       
    K9 = [bitxor(K10(1), bitxor(sboxc.sbox(bitxor(K10(14),K10(10))+1), 54)) ...
          bitxor(K10(2), sboxc.sbox(bitxor(K10(15),K10(11))+1)) ...
          bitxor(K10(3), sboxc.sbox(bitxor(K10(16),K10(12))+1)) ...
          bitxor(K10(4), sboxc.sbox(bitxor(K10(13),K10(9))+1)) ...
          bitxor(K10(5), K10(1)) ...
          bitxor(K10(6), K10(2)) ...
          bitxor(K10(7), K10(3)) ...
          bitxor(K10(8), K10(4)) ...
          bitxor(K10(9), K10(5)) ...
          bitxor(K10(10), K10(6)) ...
          bitxor(K10(11), K10(7)) ...
          bitxor(K10(12), K10(8)) ...
          bitxor(K10(13), K10(9)) ...
          bitxor(K10(14), K10(10)) ...
          bitxor(K10(15), K10(11)) ...
          bitxor(K10(16), K10(12)) ...
          ];
    
    % we assume initially that the chose K10 passes the constraints
    key_is_invalid = 0;
    
    % for all traces
    for j=1:size(ciphertext,1)

        % compute the input to the last round I10 using the ciphertext C and the 
        % last round key K10

        % inverse addroundkey
        C = ciphertext(j,:);
        T1 = bitxor(C, K10);

        % inverse shiftrows
        T2 = [T1(1) T1(14) T1(11) T1(8) T1(5) T1(2) T1(15) T1(12) T1(9) T1(6) T1(3) T1(16) T1(13) T1(10) T1(7) T1(4)];

        % inverse faulty sbox
        % - filter here for the unlikely case that we have
        % to invert the missing v (which is impossible to do with the
        % faulty)
        % - filter here also for the case that we have to invert the
        % duplicate value (which is not a one-to-one mapping)
        if (~ismember(v_correct, T2)) && (~ismember(v_faulty, T2))

            I10 = zeros(1,16);
            for index=1:16
                I10(index) = sboxc.inv_sbox(T2(index)+1);
            end
            
            % inverse addroundkey
            T4 = bitxor(I10, K9);

            % inverse MC
            T4_square = reshape(T4, 4, 4);
            T5_square = InvMixColumns(T4_square);
            target = reshape(T5_square,1,16);
            
            
            % apply the constraints for the penultimate round
            % we do it in a straightforward manner instead of the 10-13
            % byte types that can optimize a bit the situation for AES
            if ismember(v_correct, target)
                
                % discard the round key K10, I dont need to check more
                % ciphertexts
                key_is_invalid = 1;
                break;
            end

        end
        
    end
    
    % if the coniditions are met for all ciphertexts
    if key_is_invalid == 0
        K10_sieved_candidates(counter,:) = K10;
        counter = counter + 1;
    end
    
end

% compare the K10 candidates after PFA on the last round with the 'sieved'
% K10 candidates after the 9th round constraints
size(K10_sieved_candidates,1);
size(K10_candidates,1);

       

    
end

