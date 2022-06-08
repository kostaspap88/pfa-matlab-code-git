% initialize the matrices that contain the attack results for various PFA
% attacks
function result = initialize_result(len_vec, no_attacks)

result.key_singlesbox = zeros(1);
result.key_full_strategy1_all = zeros(16, len_vec, no_attacks);
result.key_full_strategy2_all = zeros(16, len_vec, no_attacks);
result.key_full_strategy3_all = zeros(16, len_vec, no_attacks);
result.key_full_mlesteps_all = zeros(16, len_vec, no_attacks);
result.key_full_mlelogprob_all = zeros(16, len_vec, no_attacks);
result.key_full_unknownfault_all = zeros(16, len_vec, no_attacks);
result.key_full_unknownfault_unknownposition_all = zeros(16, len_vec, no_attacks);
% result.key_byte_spfa_all = zeros(length(no_traces_vector), no_attacks);

end