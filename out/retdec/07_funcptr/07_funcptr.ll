source_filename = "test"
target datalayout = "e-m:e-p:64:64-i64:64-f80:128-n8:16:32:64-S128"

@global_var_403fe0 = local_unnamed_addr global i64 0
@global_var_402004 = constant [4 x i8] c"%d\0A\00"
@global_var_404018 = local_unnamed_addr global i8 0

define i64 @main(i64 %argc, i8** %argv) local_unnamed_addr {
dec_label_pc_40115f:
  %0 = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([4 x i8], [4 x i8]* @global_var_402004, i64 0, i64 0), i64 7), !insn.addr !0
  ret i64 0, !insn.addr !1
}

declare i32 @printf(i8*, ...) local_unnamed_addr

!0 = !{i64 4198863}
!1 = !{i64 4198874}
