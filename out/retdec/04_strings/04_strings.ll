source_filename = "test"
target datalayout = "e-m:e-p:64:64-i64:64-f80:128-n8:16:32:64-S128"

@global_var_403fe0 = local_unnamed_addr global i64 0
@global_var_402004 = constant [6 x i8] c"Flash\00"
@global_var_40200a = constant [5 x i8] c"back\00"
@global_var_40200f = constant [5 x i8] c"%s%s\00"
@global_var_402014 = constant [12 x i8] c"%s len=%zu\0A\00"
@global_var_404028 = local_unnamed_addr global i8 0

define i64 @main(i64 %argc, i8** %argv) local_unnamed_addr {
dec_label_pc_401146:
  %stack_var_-88 = alloca i64, align 8
  %0 = bitcast i64* %stack_var_-88 to i8*, !insn.addr !0
  %1 = call i32 (i8*, i32, i8*, ...) @snprintf(i8* nonnull %0, i32 64, i8* getelementptr inbounds ([5 x i8], [5 x i8]* @global_var_40200f, i64 0, i64 0), i8* getelementptr inbounds ([6 x i8], [6 x i8]* @global_var_402004, i64 0, i64 0), i8* getelementptr inbounds ([5 x i8], [5 x i8]* @global_var_40200a, i64 0, i64 0)), !insn.addr !0
  %2 = call i32 @strlen(i8* nonnull %0), !insn.addr !1
  %3 = sext i32 %2 to i64, !insn.addr !1
  %4 = ptrtoint i64* %stack_var_-88 to i64, !insn.addr !2
  %5 = add i64 %3, %4, !insn.addr !3
  %6 = inttoptr i64 %5 to i16*, !insn.addr !4
  store i16 33, i16* %6, align 2, !insn.addr !4
  %7 = call i32 @strlen(i8* nonnull %0), !insn.addr !5
  %8 = sext i32 %7 to i64, !insn.addr !5
  %9 = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([12 x i8], [12 x i8]* @global_var_402014, i64 0, i64 0), i64* nonnull %stack_var_-88, i64 %8), !insn.addr !6
  ret i64 0, !insn.addr !7

; uselistorder directives
  uselistorder i64* %stack_var_-88, { 0, 2, 1 }
  uselistorder i32 (i8*)* @strlen, { 1, 0 }
}

declare i32 @strlen(i8*) local_unnamed_addr

declare i32 @printf(i8*, ...) local_unnamed_addr

declare i32 @snprintf(i8*, i32, i8*, ...) local_unnamed_addr

!0 = !{i64 4198794}
!1 = !{i64 4198806}
!2 = !{i64 4198814}
!3 = !{i64 4198818}
!4 = !{i64 4198821}
!5 = !{i64 4198833}
!6 = !{i64 4198863}
!7 = !{i64 4198874}
