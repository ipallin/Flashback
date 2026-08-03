source_filename = "test"
target datalayout = "e-m:e-p:64:64-i64:64-f80:128-n8:16:32:64-S128"

@global_var_403fe0 = local_unnamed_addr global i64 0
@global_var_402004 = constant [4 x i8] c"%d\0A\00"
@global_var_404018 = local_unnamed_addr global i8 0

define i64 @main(i64 %argc, i8** %argv) local_unnamed_addr {
dec_label_pc_401126:
  %stack_var_-12.0.reg2mem = alloca i32, !insn.addr !0
  %stack_var_-12.11.reg2mem = alloca i32, !insn.addr !0
  %storemerge3.reg2mem = alloca i32, !insn.addr !0
  store i32 0, i32* %storemerge3.reg2mem
  store i32 0, i32* %stack_var_-12.11.reg2mem
  br label %dec_label_pc_40113e

dec_label_pc_40113e:                              ; preds = %dec_label_pc_401181, %dec_label_pc_401126
  %stack_var_-12.11.reload = load i32, i32* %stack_var_-12.11.reg2mem
  %storemerge3.reload = load i32, i32* %storemerge3.reg2mem
  %0 = icmp eq i32 %storemerge3.reload, 3, !insn.addr !1
  br i1 %0, label %dec_label_pc_401176, label %dec_label_pc_401144, !insn.addr !2

dec_label_pc_401144:                              ; preds = %dec_label_pc_40113e
  %1 = icmp ugt i32 %storemerge3.reload, 3, !insn.addr !3
  br i1 %1, label %dec_label_pc_40117c, label %dec_label_pc_40114a, !insn.addr !3

dec_label_pc_40114a:                              ; preds = %dec_label_pc_401144
  %2 = icmp eq i32 %storemerge3.reload, 2, !insn.addr !4
  br i1 %2, label %dec_label_pc_401170, label %dec_label_pc_401150, !insn.addr !5

dec_label_pc_401150:                              ; preds = %dec_label_pc_40114a
  %3 = icmp ugt i32 %storemerge3.reload, 2, !insn.addr !6
  br i1 %3, label %dec_label_pc_40117c, label %dec_label_pc_401156, !insn.addr !6

dec_label_pc_401156:                              ; preds = %dec_label_pc_401150
  switch i32 %storemerge3.reload, label %dec_label_pc_40117c [
    i32 0, label %dec_label_pc_401164
    i32 1, label %dec_label_pc_40116a
  ]

dec_label_pc_401164:                              ; preds = %dec_label_pc_401156
  %4 = add i32 %stack_var_-12.11.reload, 10, !insn.addr !7
  store i32 %4, i32* %stack_var_-12.0.reg2mem, !insn.addr !8
  br label %dec_label_pc_401181, !insn.addr !8

dec_label_pc_40116a:                              ; preds = %dec_label_pc_401156
  %5 = add i32 %stack_var_-12.11.reload, 20, !insn.addr !9
  store i32 %5, i32* %stack_var_-12.0.reg2mem, !insn.addr !10
  br label %dec_label_pc_401181, !insn.addr !10

dec_label_pc_401170:                              ; preds = %dec_label_pc_40114a
  %6 = add i32 %stack_var_-12.11.reload, 30, !insn.addr !11
  store i32 %6, i32* %stack_var_-12.0.reg2mem, !insn.addr !12
  br label %dec_label_pc_401181, !insn.addr !12

dec_label_pc_401176:                              ; preds = %dec_label_pc_40113e
  %7 = add i32 %stack_var_-12.11.reload, 40, !insn.addr !13
  store i32 %7, i32* %stack_var_-12.0.reg2mem, !insn.addr !14
  br label %dec_label_pc_401181, !insn.addr !14

dec_label_pc_40117c:                              ; preds = %dec_label_pc_401156, %dec_label_pc_401150, %dec_label_pc_401144
  %8 = add i32 %stack_var_-12.11.reload, 50, !insn.addr !15
  store i32 %8, i32* %stack_var_-12.0.reg2mem, !insn.addr !16
  br label %dec_label_pc_401181, !insn.addr !16

dec_label_pc_401181:                              ; preds = %dec_label_pc_40117c, %dec_label_pc_401176, %dec_label_pc_401170, %dec_label_pc_40116a, %dec_label_pc_401164
  %stack_var_-12.0.reload = load i32, i32* %stack_var_-12.0.reg2mem
  %9 = add nuw nsw i32 %storemerge3.reload, 1, !insn.addr !17
  %exitcond = icmp eq i32 %9, 5
  store i32 %9, i32* %storemerge3.reg2mem, !insn.addr !18
  store i32 %stack_var_-12.0.reload, i32* %stack_var_-12.11.reg2mem, !insn.addr !18
  br i1 %exitcond, label %dec_label_pc_40118b, label %dec_label_pc_40113e, !insn.addr !18

dec_label_pc_40118b:                              ; preds = %dec_label_pc_401181
  %10 = zext i32 %stack_var_-12.0.reload to i64, !insn.addr !19
  %11 = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([4 x i8], [4 x i8]* @global_var_402004, i64 0, i64 0), i64 %10), !insn.addr !20
  ret i64 0, !insn.addr !21

; uselistorder directives
  uselistorder i32 %storemerge3.reload, { 5, 0, 1, 2, 3, 4 }
  uselistorder i32 %stack_var_-12.11.reload, { 4, 3, 2, 0, 1 }
  uselistorder i32* %storemerge3.reg2mem, { 1, 0, 2 }
  uselistorder i32* %stack_var_-12.11.reg2mem, { 1, 0, 2 }
  uselistorder i32* %stack_var_-12.0.reg2mem, { 0, 4, 5, 3, 1, 2 }
  uselistorder i32 2, { 1, 0 }
  uselistorder i32 3, { 1, 0 }
  uselistorder i32 0, { 2, 0, 1 }
  uselistorder i32 1, { 4, 3, 2, 1, 0 }
}

declare i32 @printf(i8*, ...) local_unnamed_addr

!0 = !{i64 4198694}
!1 = !{i64 4198718}
!2 = !{i64 4198722}
!3 = !{i64 4198728}
!4 = !{i64 4198730}
!5 = !{i64 4198734}
!6 = !{i64 4198740}
!7 = !{i64 4198756}
!8 = !{i64 4198760}
!9 = !{i64 4198762}
!10 = !{i64 4198766}
!11 = !{i64 4198768}
!12 = !{i64 4198772}
!13 = !{i64 4198774}
!14 = !{i64 4198778}
!15 = !{i64 4198780}
!16 = !{i64 4198784}
!17 = !{i64 4198785}
!18 = !{i64 4198793}
!19 = !{i64 4198798}
!20 = !{i64 4198815}
!21 = !{i64 4198826}
