source_filename = "test"
target datalayout = "e-m:e-p:64:64-i64:64-f80:128-n8:16:32:64-S128"

@global_var_403fe0 = local_unnamed_addr global i64 0
@global_var_402004 = constant [5 x i8] c"%ld\0A\00"
@global_var_404018 = local_unnamed_addr global i8 0

define i64 @main(i64 %argc, i8** %argv) local_unnamed_addr {
dec_label_pc_401126:
  %stack_var_-16.16.reg2mem = alloca i32, !insn.addr !0
  %storemerge7.reg2mem = alloca i32, !insn.addr !0
  %stack_var_-16.0.lcssa.reg2mem = alloca i32, !insn.addr !0
  %storemerge3.in.reg2mem = alloca i32, !insn.addr !0
  %stack_var_-24.04.reg2mem = alloca i32, !insn.addr !0
  %stack_var_-16.05.reg2mem = alloca i32, !insn.addr !0
  store i32 1, i32* %storemerge7.reg2mem
  store i32 0, i32* %stack_var_-16.16.reg2mem
  br label %dec_label_pc_401173.preheader

dec_label_pc_401147:                              ; preds = %dec_label_pc_401173.preheader, %dec_label_pc_40116b
  %stack_var_-24.04.reload = load i32, i32* %stack_var_-24.04.reg2mem
  %stack_var_-16.05.reload = load i32, i32* %stack_var_-16.05.reg2mem
  %0 = urem i32 %stack_var_-24.04.reload, 2, !insn.addr !1
  %1 = icmp eq i32 %0, 0, !insn.addr !2
  %2 = icmp eq i1 %1, false, !insn.addr !3
  br i1 %2, label %dec_label_pc_40115f, label %dec_label_pc_401151, !insn.addr !3

dec_label_pc_401151:                              ; preds = %dec_label_pc_401147
  %3 = icmp slt i32 %stack_var_-24.04.reload, 0
  %4 = zext i1 %3 to i32, !insn.addr !4
  %5 = add i32 %stack_var_-24.04.reload, %4, !insn.addr !5
  %6 = ashr i32 %5, 1, !insn.addr !6
  store i32 %6, i32* %storemerge3.in.reg2mem, !insn.addr !7
  br label %dec_label_pc_40116b, !insn.addr !7

dec_label_pc_40115f:                              ; preds = %dec_label_pc_401147
  %7 = mul i32 %stack_var_-24.04.reload, 3, !insn.addr !8
  %8 = add i32 %7, 1, !insn.addr !9
  store i32 %8, i32* %storemerge3.in.reg2mem, !insn.addr !9
  br label %dec_label_pc_40116b, !insn.addr !9

dec_label_pc_40116b:                              ; preds = %dec_label_pc_40115f, %dec_label_pc_401151
  %storemerge3.in.reload = load i32, i32* %storemerge3.in.reg2mem
  %9 = add i32 %stack_var_-16.05.reload, 1, !insn.addr !10
  %10 = icmp eq i32 %storemerge3.in.reload, 1, !insn.addr !11
  %11 = icmp eq i1 %10, false, !insn.addr !12
  store i32 %9, i32* %stack_var_-16.05.reg2mem, !insn.addr !12
  store i32 %storemerge3.in.reload, i32* %stack_var_-24.04.reg2mem, !insn.addr !12
  store i32 %9, i32* %stack_var_-16.0.lcssa.reg2mem, !insn.addr !12
  br i1 %11, label %dec_label_pc_401147, label %dec_label_pc_401179, !insn.addr !12

dec_label_pc_401179:                              ; preds = %dec_label_pc_40116b, %dec_label_pc_401173.preheader
  %stack_var_-16.0.lcssa.reload = load i32, i32* %stack_var_-16.0.lcssa.reg2mem
  %12 = add nuw nsw i32 %storemerge7.reload, 1, !insn.addr !13
  %exitcond = icmp eq i32 %12, 101
  store i32 %12, i32* %storemerge7.reg2mem, !insn.addr !14
  store i32 %stack_var_-16.0.lcssa.reload, i32* %stack_var_-16.16.reg2mem, !insn.addr !14
  br i1 %exitcond, label %dec_label_pc_401183, label %dec_label_pc_401173.preheader, !insn.addr !14

dec_label_pc_401173.preheader:                    ; preds = %dec_label_pc_401179, %dec_label_pc_401126
  %stack_var_-16.16.reload = load i32, i32* %stack_var_-16.16.reg2mem
  %storemerge7.reload = load i32, i32* %storemerge7.reg2mem
  %13 = icmp eq i32 %storemerge7.reload, 1, !insn.addr !11
  %14 = icmp eq i1 %13, false, !insn.addr !12
  store i32 %stack_var_-16.16.reload, i32* %stack_var_-16.05.reg2mem, !insn.addr !12
  store i32 %storemerge7.reload, i32* %stack_var_-24.04.reg2mem, !insn.addr !12
  store i32 %stack_var_-16.16.reload, i32* %stack_var_-16.0.lcssa.reg2mem, !insn.addr !12
  br i1 %14, label %dec_label_pc_401147, label %dec_label_pc_401179, !insn.addr !12

dec_label_pc_401183:                              ; preds = %dec_label_pc_401179
  %15 = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([5 x i8], [5 x i8]* @global_var_402004, i64 0, i64 0), i32 %stack_var_-16.0.lcssa.reload), !insn.addr !15
  ret i64 0, !insn.addr !16

; uselistorder directives
  uselistorder i32 %storemerge7.reload, { 2, 0, 1 }
  uselistorder i32 %stack_var_-16.16.reload, { 1, 0 }
  uselistorder i32 %stack_var_-16.0.lcssa.reload, { 1, 0 }
  uselistorder i32 %storemerge3.in.reload, { 1, 0 }
  uselistorder i32 %stack_var_-24.04.reload, { 0, 3, 2, 1 }
  uselistorder i32* %stack_var_-16.05.reg2mem, { 1, 2, 0 }
  uselistorder i32* %stack_var_-24.04.reg2mem, { 1, 2, 0 }
  uselistorder i32* %storemerge3.in.reg2mem, { 0, 2, 1 }
  uselistorder i32* %stack_var_-16.0.lcssa.reg2mem, { 2, 0, 1 }
  uselistorder i1 false, { 0, 2, 1 }
  uselistorder i32 0, { 1, 2, 0 }
  uselistorder i32 1, { 7, 12, 9, 8, 10, 11, 1, 6, 5, 4, 3, 2, 0 }
  uselistorder label %dec_label_pc_401179, { 1, 0 }
}

declare i32 @printf(i8*, ...) local_unnamed_addr

!0 = !{i64 4198694}
!1 = !{i64 4198730}
!2 = !{i64 4198733}
!3 = !{i64 4198735}
!4 = !{i64 4198742}
!5 = !{i64 4198745}
!6 = !{i64 4198747}
!7 = !{i64 4198749}
!8 = !{i64 4198758}
!9 = !{i64 4198760}
!10 = !{i64 4198766}
!11 = !{i64 4198771}
!12 = !{i64 4198775}
!13 = !{i64 4198777}
!14 = !{i64 4198785}
!15 = !{i64 4198809}
!16 = !{i64 4198820}
