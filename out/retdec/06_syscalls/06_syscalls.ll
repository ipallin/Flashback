source_filename = "test"
target datalayout = "e-m:e-p:64:64-i64:64-f80:128-n8:16:32:64-S128"

@global_var_403fe0 = local_unnamed_addr global i64 0
@0 = external global i32
@global_var_404020 = local_unnamed_addr global i8 0

define i64 @main(i64 %argc, i8** %argv) local_unnamed_addr {
dec_label_pc_401136:
  %stack_var_-23 = alloca i64, align 8
  store i64 3273110194727647603, i64* %stack_var_-23, align 8, !insn.addr !0
  %0 = call i32 @write(i32 1, i64* nonnull %stack_var_-23, i32 14), !insn.addr !1
  call void @_exit(i32 0), !insn.addr !2
  ret i64 ptrtoint (i32* @0 to i64), !insn.addr !2
}

declare void @_exit(i32) local_unnamed_addr

declare i32 @write(i32, i64*, i32) local_unnamed_addr

!0 = !{i64 4198728}
!1 = !{i64 4198763}
!2 = !{i64 4198773}
