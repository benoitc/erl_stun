-define(STUN_MAGIC, 554869826).

-record(stun, {method,
               class,
               magic=?STUN_MAGIC,
               transaction_id,
               attrs=[]}).
