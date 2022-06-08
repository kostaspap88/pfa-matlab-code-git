function State = MixColumns(state)
State=state;

% Original MixColumns
for a=1:4:13
    State(a)=bitxor(bitxor(bitxor(xtime(state(a),2),xtime(state(a+1),3)),state(a+2)),state(a+3));
    State(a+1)=bitxor(bitxor(bitxor(xtime(state(a+1),2),xtime(state(a+2),3)),state(a)),state(a+3));
    State(a+2)=bitxor(bitxor(bitxor(xtime(state(a+2),2),xtime(state(a+3),3)),state(a)),state(a+1));
    State(a+3)=bitxor(bitxor(bitxor(xtime(state(a+3),2),xtime(state(a),3)),state(a+1)),state(a+2));
end

% Modified MixColumns
% alpha = 5;
% beta = 10;
% gamma = 12;
% delta = 3;
% 
% % condition1 = bitxor(bitxor(alpha, beta),gamma)
% % condition2 = bitxor(bitxor(alpha, beta),delta)
% % condition3 = bitxor(bitxor(alpha, gamma),delta)
% % condition4 = bitxor(bitxor(beta, gamma),delta)
% 
% for a=1:4:13
%     State(a)=bitxor(bitxor(bitxor(xtime(state(a),alpha),xtime(state(a+1),beta)),xtime(state(a+2),gamma)),xtime(state(a+3),delta));
%     State(a+1)=bitxor(bitxor(bitxor(xtime(state(a+1),alpha),xtime(state(a+2),beta)),xtime(state(a),delta)),xtime(state(a+3),gamma));
%     State(a+2)=bitxor(bitxor(bitxor(xtime(state(a+2),alpha),xtime(state(a+3),beta)),xtime(state(a),gamma)),xtime(state(a+1),delta));
%     State(a+3)=bitxor(bitxor(bitxor(xtime(state(a+3),alpha),xtime(state(a),beta)),xtime(state(a+1),gamma)),xtime(state(a+2),delta));
% end


end