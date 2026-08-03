source_filename = "test"
target datalayout = "e-m:e-p:64:64-i64:64-f80:128-n8:16:32:64-S128"

@global_var_403fe0 = local_unnamed_addr global i64 0
@global_var_402004 = constant [11 x i8] c"Hello, %d\0A\00"
@global_var_404018 = local_unnamed_addr global i8 0

define i64 @aux(i64 %arg1) local_unnamed_addr {
dec_label_pc_401126:
  %0 = add i64 %arg1, 1, !insn.addr !0
  %1 = and i64 %0, 4294967295, !insn.addr !0
  ret i64 %1, !insn.addr !1
}

define i64 @main(i64 %argc, i8** %argv) local_unnamed_addr {
dec_label_pc_401135:
  %0 = call i64 @aux(i64 41), !insn.addr !2
  %1 = and i64 %0, 4294967295, !insn.addr !3
  %2 = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([11 x i8], [11 x i8]* @global_var_402004, i64 0, i64 0), i64 %1), !insn.addr !4
  ret i64 0, !insn.addr !5
}

declare i32 @printf(i8*, ...) local_unnamed_addr

!0 = !{i64 4198704}
!1 = !{i64 4198708}
!2 = !{i64 4198718}
!3 = !{i64 4198723}
!4 = !{i64 4198740}
!5 = !{i64 4198751}
