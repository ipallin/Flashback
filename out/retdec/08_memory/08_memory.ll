source_filename = "test"
target datalayout = "e-m:e-p:64:64-i64:64-f80:128-n8:16:32:64-S128"

@global_var_403fe0 = local_unnamed_addr global i64 0
@global_var_402004 = constant [5 x i8] c"%ld\0A\00"
@global_var_404030 = local_unnamed_addr global i8 0

define i64 @main(i64 %argc, i8** %argv) local_unnamed_addr {
dec_label_pc_401156:
  %stack_var_-24.03.reg2mem = alloca i32, !insn.addr !0
  %indvars.iv.reg2mem = alloca i64, !insn.addr !0
  %indvars.iv6.reg2mem = alloca i64, !insn.addr !0
  %0 = call i64* @malloc(i32 32), !insn.addr !1
  %1 = ptrtoint i64* %0 to i64, !insn.addr !1
  store i64 0, i64* %indvars.iv6.reg2mem
  br label %dec_label_pc_401175

dec_label_pc_401175:                              ; preds = %dec_label_pc_401175, %dec_label_pc_401156
  %indvars.iv6.reload = load i64, i64* %indvars.iv6.reg2mem
  %2 = mul i64 %indvars.iv6.reload, 4, !insn.addr !2
  %3 = add i64 %2, %1, !insn.addr !3
  %4 = trunc i64 %indvars.iv6.reload to i32
  %5 = mul i32 %4, %4, !insn.addr !4
  %6 = inttoptr i64 %3 to i32*, !insn.addr !5
  store i32 %5, i32* %6, align 4, !insn.addr !5
  %indvars.iv.next7 = add nuw nsw i64 %indvars.iv6.reload, 1
  %exitcond8 = icmp eq i64 %indvars.iv.next7, 8
  store i64 %indvars.iv.next7, i64* %indvars.iv6.reg2mem, !insn.addr !6
  br i1 %exitcond8, label %dec_label_pc_40119b, label %dec_label_pc_401175, !insn.addr !6

dec_label_pc_40119b:                              ; preds = %dec_label_pc_401175
  %7 = call i64* @realloc(i64* %0, i32 64), !insn.addr !7
  %8 = ptrtoint i64* %7 to i64, !insn.addr !7
  store i64 0, i64* %indvars.iv.reg2mem
  store i32 0, i32* %stack_var_-24.03.reg2mem
  br label %dec_label_pc_4011c1

dec_label_pc_4011c1:                              ; preds = %dec_label_pc_4011c1, %dec_label_pc_40119b
  %stack_var_-24.03.reload = load i32, i32* %stack_var_-24.03.reg2mem
  %indvars.iv.reload = load i64, i64* %indvars.iv.reg2mem
  %9 = mul i64 %indvars.iv.reload, 4, !insn.addr !8
  %10 = add i64 %9, %8, !insn.addr !9
  %11 = inttoptr i64 %10 to i32*, !insn.addr !10
  %12 = load i32, i32* %11, align 4, !insn.addr !10
  %13 = add i32 %12, %stack_var_-24.03.reload, !insn.addr !11
  %indvars.iv.next = add nuw nsw i64 %indvars.iv.reload, 1
  %exitcond = icmp eq i64 %indvars.iv.next, 8
  store i64 %indvars.iv.next, i64* %indvars.iv.reg2mem, !insn.addr !12
  store i32 %13, i32* %stack_var_-24.03.reg2mem, !insn.addr !12
  br i1 %exitcond, label %dec_label_pc_4011e7, label %dec_label_pc_4011c1, !insn.addr !12

dec_label_pc_4011e7:                              ; preds = %dec_label_pc_4011c1
  call void @free(i64* %7), !insn.addr !13
  %14 = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([5 x i8], [5 x i8]* @global_var_402004, i64 0, i64 0), i32 %13), !insn.addr !14
  ret i64 0, !insn.addr !15

; uselistorder directives
  uselistorder i32 %13, { 1, 0 }
  uselistorder i64* %indvars.iv6.reg2mem, { 1, 0, 2 }
  uselistorder i64* %indvars.iv.reg2mem, { 1, 0, 2 }
  uselistorder i32* %stack_var_-24.03.reg2mem, { 1, 0, 2 }
  uselistorder i64 8, { 1, 0 }
  uselistorder i64 1, { 1, 0 }
  uselistorder i64 0, { 2, 3, 4, 0, 1, 5 }
  uselistorder i32 1, { 2, 1, 0 }
}

declare void @free(i64*) local_unnamed_addr

declare i32 @printf(i8*, ...) local_unnamed_addr

declare i64* @malloc(i32) local_unnamed_addr

declare i64* @realloc(i64*, i32) local_unnamed_addr

!0 = !{i64 4198742}
!1 = !{i64 4198755}
!2 = !{i64 4198778}
!3 = !{i64 4198790}
!4 = !{i64 4198796}
!5 = !{i64 4198799}
!6 = !{i64 4198809}
!7 = !{i64 4198823}
!8 = !{i64 4198854}
!9 = !{i64 4198866}
!10 = !{i64 4198869}
!11 = !{i64 4198873}
!12 = !{i64 4198885}
!13 = !{i64 4198894}
!14 = !{i64 4198921}
!15 = !{i64 4198932}
