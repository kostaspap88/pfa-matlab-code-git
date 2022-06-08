function [sei] = squared_euclidian_imbalance(intermediate, vsize)


sei = sum((histcounts(intermediate, vsize)/size(intermediate,1) - 1/vsize).^2);


end