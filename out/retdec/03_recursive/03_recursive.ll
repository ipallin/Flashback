source_filename = "test"
target datalayout = "e-m:e-p:64:64-i64:64-f80:128-n8:16:32:64-S128"

@global_var_403fe0 = local_unnamed_addr global i64 0
@global_var_402004 = constant [7 x i8] c"%d %d\0A\00"
@global_var_404018 = local_unnamed_addr global i8 0

define i64 @fib(i64 %arg1) local_unnamed_addr {
dec_label_pc_401126:
  %storemerge.in.reg2mem = alloca i64, !insn.addr !0
  %0 = trunc i64 %arg1 to i32, !insn.addr !1
  %sext = mul i64 %arg1, 4294967296
  %1 = ashr exact i64 %sext, 32, !insn.addr !1
  %2 = icmp slt i32 %0, 2, !insn.addr !2
  store i64 %1, i64* %storemerge.in.reg2mem, !insn.addr !2
  br i1 %2, label %dec_label_pc_40115b, label %dec_label_pc_401138, !insn.addr !2

dec_label_pc_401138:                              ; preds = %dec_label_pc_401126
  %3 = add nsw i64 %1, 4294967295, !insn.addr !3
  %4 = and i64 %3, 4294967295, !insn.addr !4
  %5 = call i64 @fib(i64 %4), !insn.addr !5
  %6 = add nsw i64 %1, 4294967294, !insn.addr !6
  %7 = and i64 %6, 4294967295, !insn.addr !7
  %8 = call i64 @fib(i64 %7), !insn.addr !8
  %9 = add i64 %8, %5, !insn.addr !9
  store i64 %9, i64* %storemerge.in.reg2mem, !insn.addr !10
  br label %dec_label_pc_40115b, !insn.addr !10

dec_label_pc_40115b:                              ; preds = %dec_label_pc_401126, %dec_label_pc_401138
  %storemerge.in.reload = load i64, i64* %storemerge.in.reg2mem
  %storemerge = and i64 %storemerge.in.reload, 4294967295
  ret i64 %storemerge, !insn.addr !11

; uselistorder directives
  uselistorder i64 %1, { 1, 2, 0 }
  uselistorder i64* %storemerge.in.reg2mem, { 0, 2, 1 }
  uselistorder label %dec_label_pc_40115b, { 1, 0 }
}

define i64 @is_even(i64 %arg1) local_unnamed_addr {
dec_label_pc_401161:
  %0 = trunc i64 %arg1 to i32, !insn.addr !12
  %1 = icmp eq i32 %0, 0, !insn.addr !13
  br i1 %1, label %dec_label_pc_40118f, label %dec_label_pc_401172, !insn.addr !14

dec_label_pc_401172:                              ; preds = %dec_label_pc_401161
  %2 = add i64 %arg1, 4294967295, !insn.addr !15
  %3 = and i64 %2, 4294967295, !insn.addr !16
  %4 = call i64 @is_even(i64 %3), !insn.addr !17
  %5 = trunc i64 %4 to i32, !insn.addr !18
  %6 = icmp eq i32 %5, 0, !insn.addr !18
  %spec.select = zext i1 %6 to i64
  ret i64 %spec.select

dec_label_pc_40118f:                              ; preds = %dec_label_pc_401161
  ret i64 1, !insn.addr !19
}

define i64 @main(i64 %argc, i8** %argv) local_unnamed_addr {
dec_label_pc_401191:
  %0 = call i64 @is_even(i64 8), !insn.addr !20
  %1 = call i64 @fib(i64 10), !insn.addr !21
  %2 = and i64 %0, 4294967295, !insn.addr !22
  %3 = and i64 %1, 4294967295, !insn.addr !23
  %4 = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([7 x i8], [7 x i8]* @global_var_402004, i64 0, i64 0), i64 %3, i64 %2), !insn.addr !24
  ret i64 0, !insn.addr !25

; uselistorder directives
  uselistorder i64 (i64)* @fib, { 2, 1, 0 }
  uselistorder i64 (i64)* @is_even, { 1, 0 }
}

declare i32 @printf(i8*, ...) local_unnamed_addr

!0 = !{i64 4198694}
!1 = !{i64 4198703}
!2 = !{i64 4198710}
!3 = !{i64 4198715}
!4 = !{i64 4198718}
!5 = !{i64 4198720}
!6 = !{i64 4198730}
!7 = !{i64 4198733}
!8 = !{i64 4198735}
!9 = !{i64 4198740}
!10 = !{i64 4198742}
!11 = !{i64 4198752}
!12 = !{i64 4198761}
!13 = !{i64 4198764}
!14 = !{i64 4198768}
!15 = !{i64 4198773}
!16 = !{i64 4198776}
!17 = !{i64 4198778}
!18 = !{i64 4198783}
!19 = !{i64 4198800}
!20 = !{i64 4198815}
!21 = !{i64 4198827}
!22 = !{i64 4198832}
!23 = !{i64 4198834}
!24 = !{i64 4198851}
!25 = !{i64 4198866}
