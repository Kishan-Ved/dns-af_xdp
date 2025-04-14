; ModuleID = 'dns_filter_kern.c'
source_filename = "dns_filter_kern.c"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

%struct.anon.5 = type { [17 x i32]*, i32*, i32*, [64 x i32]*, [1 x i32]* }
%struct.anon.6 = type { [6 x i32]*, i32*, i32*, [64 x i32]* }
%struct.xdp_md = type { i32, i32, i32, i32, i32, i32 }
%struct.ethhdr = type { [6 x i8], [6 x i8], i16 }
%struct.hdr_cursor = type { i8* }
%struct.iphdr = type { i8, i8, i16, i16, i16, i8, i8, i16, %union.anon }
%union.anon = type { %struct.anon }
%struct.anon = type { i32, i32 }
%struct.ipv6hdr = type { i8, [3 x i8], i16, i8, i8, %union.anon.1 }
%union.anon.1 = type { %struct.anon.2 }
%struct.anon.2 = type { %struct.in6_addr, %struct.in6_addr }
%struct.in6_addr = type { %union.anon.3 }
%union.anon.3 = type { [4 x i32] }
%struct.udphdr = type { i16, i16, i16, i16 }

@xsks_map = dso_local global %struct.anon.5 zeroinitializer, section ".maps", align 8, !dbg !0
@_license = dso_local global [4 x i8] c"GPL\00", section "license", align 1, !dbg !52
@xdp_stats_map = dso_local global %struct.anon.6 zeroinitializer, section ".maps", align 8, !dbg !58
@llvm.compiler.used = appending global [4 x i8*] [i8* getelementptr inbounds ([4 x i8], [4 x i8]* @_license, i32 0, i32 0), i8* bitcast (i32 (%struct.xdp_md*)* @xdp_dns_filter_func to i8*), i8* bitcast (%struct.anon.6* @xdp_stats_map to i8*), i8* bitcast (%struct.anon.5* @xsks_map to i8*)], section "llvm.metadata"

; Function Attrs: nounwind
define dso_local i32 @xdp_dns_filter_func(%struct.xdp_md* nocapture noundef readonly %0) #0 section "xdp_dns_filter" !dbg !112 {
  %2 = alloca i32, align 4
  call void @llvm.dbg.value(metadata %struct.xdp_md* %0, metadata !125, metadata !DIExpression()), !dbg !230
  %3 = getelementptr inbounds %struct.xdp_md, %struct.xdp_md* %0, i64 0, i32 1, !dbg !231
  %4 = load i32, i32* %3, align 4, !dbg !231, !tbaa !232
  %5 = zext i32 %4 to i64, !dbg !237
  %6 = inttoptr i64 %5 to i8*, !dbg !238
  call void @llvm.dbg.value(metadata i8* %6, metadata !126, metadata !DIExpression()), !dbg !230
  %7 = getelementptr inbounds %struct.xdp_md, %struct.xdp_md* %0, i64 0, i32 0, !dbg !239
  %8 = load i32, i32* %7, align 4, !dbg !239, !tbaa !240
  %9 = zext i32 %8 to i64, !dbg !241
  %10 = inttoptr i64 %9 to i8*, !dbg !242
  call void @llvm.dbg.value(metadata i8* %10, metadata !127, metadata !DIExpression()), !dbg !230
  %11 = bitcast i32* %2 to i8*, !dbg !243
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %11) #4, !dbg !243
  %12 = getelementptr inbounds %struct.xdp_md, %struct.xdp_md* %0, i64 0, i32 4, !dbg !244
  %13 = load i32, i32* %12, align 4, !dbg !244, !tbaa !245
  call void @llvm.dbg.value(metadata i32 %13, metadata !128, metadata !DIExpression()), !dbg !230
  store i32 %13, i32* %2, align 4, !dbg !246, !tbaa !247
  call void @llvm.dbg.value(metadata i8* %10, metadata !223, metadata !DIExpression()), !dbg !230
  call void @llvm.dbg.value(metadata %struct.ethhdr** undef, metadata !129, metadata !DIExpression(DW_OP_deref)), !dbg !230
  call void @llvm.dbg.value(metadata %struct.hdr_cursor* undef, metadata !248, metadata !DIExpression()), !dbg !259
  call void @llvm.dbg.value(metadata i8* %6, metadata !255, metadata !DIExpression()), !dbg !259
  call void @llvm.dbg.value(metadata %struct.ethhdr** undef, metadata !256, metadata !DIExpression()), !dbg !259
  call void @llvm.dbg.value(metadata i8* %10, metadata !257, metadata !DIExpression()), !dbg !259
  call void @llvm.dbg.value(metadata i32 14, metadata !258, metadata !DIExpression()), !dbg !259
  %14 = getelementptr i8, i8* %10, i64 14, !dbg !261
  %15 = icmp ugt i8* %14, %6, !dbg !263
  br i1 %15, label %66, label %16, !dbg !264

16:                                               ; preds = %1
  call void @llvm.dbg.value(metadata i8* %10, metadata !257, metadata !DIExpression()), !dbg !259
  call void @llvm.dbg.value(metadata i8* %14, metadata !223, metadata !DIExpression()), !dbg !230
  %17 = getelementptr inbounds i8, i8* %10, i64 12, !dbg !265
  %18 = bitcast i8* %17 to i16*, !dbg !265
  %19 = load i16, i16* %18, align 1, !dbg !265, !tbaa !266
  call void @llvm.dbg.value(metadata i16 %19, metadata !227, metadata !DIExpression(DW_OP_LLVM_convert, 16, DW_ATE_signed, DW_OP_LLVM_convert, 32, DW_ATE_signed, DW_OP_stack_value)), !dbg !230
  switch i16 %19, label %66 [
    i16 8, label %20
    i16 -8826, label %36
  ], !dbg !269

20:                                               ; preds = %16
  call void @llvm.dbg.value(metadata %struct.iphdr** undef, metadata !141, metadata !DIExpression(DW_OP_deref)), !dbg !230
  call void @llvm.dbg.value(metadata %struct.hdr_cursor* undef, metadata !270, metadata !DIExpression()), !dbg !280
  call void @llvm.dbg.value(metadata i8* %6, metadata !276, metadata !DIExpression()), !dbg !280
  call void @llvm.dbg.value(metadata %struct.iphdr** undef, metadata !277, metadata !DIExpression()), !dbg !280
  call void @llvm.dbg.value(metadata i8* %14, metadata !278, metadata !DIExpression()), !dbg !280
  %21 = getelementptr i8, i8* %10, i64 34, !dbg !284
  %22 = icmp ugt i8* %21, %6, !dbg !286
  br i1 %22, label %66, label %23, !dbg !287

23:                                               ; preds = %20
  %24 = load i8, i8* %14, align 4, !dbg !288
  %25 = shl i8 %24, 2, !dbg !289
  %26 = and i8 %25, 60, !dbg !289
  call void @llvm.dbg.value(metadata i8 %26, metadata !279, metadata !DIExpression(DW_OP_LLVM_convert, 8, DW_ATE_unsigned, DW_OP_LLVM_convert, 64, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !280
  %27 = icmp ult i8 %26, 20, !dbg !290
  br i1 %27, label %66, label %28, !dbg !292

28:                                               ; preds = %23
  %29 = zext i8 %26 to i64
  call void @llvm.dbg.value(metadata i64 %29, metadata !279, metadata !DIExpression()), !dbg !280
  %30 = getelementptr i8, i8* %14, i64 %29, !dbg !293
  %31 = icmp ugt i8* %30, %6, !dbg !295
  br i1 %31, label %66, label %32, !dbg !296

32:                                               ; preds = %28
  call void @llvm.dbg.value(metadata i8* %30, metadata !223, metadata !DIExpression()), !dbg !230
  %33 = getelementptr i8, i8* %10, i64 23, !dbg !297
  %34 = load i8, i8* %33, align 1, !dbg !297, !tbaa !298
  call void @llvm.dbg.value(metadata i8 %34, metadata !228, metadata !DIExpression(DW_OP_LLVM_convert, 8, DW_ATE_unsigned, DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !230
  %35 = icmp eq i8 %34, 17, !dbg !300
  br i1 %35, label %43, label %66, !dbg !302

36:                                               ; preds = %16
  call void @llvm.dbg.value(metadata %struct.ipv6hdr** undef, metadata !171, metadata !DIExpression(DW_OP_deref)), !dbg !230
  call void @llvm.dbg.value(metadata %struct.hdr_cursor* undef, metadata !303, metadata !DIExpression()), !dbg !312
  call void @llvm.dbg.value(metadata i8* %6, metadata !309, metadata !DIExpression()), !dbg !312
  call void @llvm.dbg.value(metadata %struct.ipv6hdr** undef, metadata !310, metadata !DIExpression()), !dbg !312
  call void @llvm.dbg.value(metadata i8* %14, metadata !311, metadata !DIExpression()), !dbg !312
  %37 = getelementptr i8, i8* %10, i64 54, !dbg !316
  %38 = icmp ugt i8* %37, %6, !dbg !318
  br i1 %38, label %66, label %39, !dbg !319

39:                                               ; preds = %36
  call void @llvm.dbg.value(metadata i8* %14, metadata !311, metadata !DIExpression()), !dbg !312
  call void @llvm.dbg.value(metadata i8* %37, metadata !223, metadata !DIExpression()), !dbg !230
  %40 = getelementptr i8, i8* %10, i64 20, !dbg !320
  %41 = load i8, i8* %40, align 2, !dbg !320, !tbaa !321
  call void @llvm.dbg.value(metadata i8 %41, metadata !228, metadata !DIExpression(DW_OP_LLVM_convert, 8, DW_ATE_unsigned, DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !230
  %42 = icmp eq i8 %41, 17, !dbg !323
  br i1 %42, label %43, label %66, !dbg !325

43:                                               ; preds = %32, %39
  %44 = phi i8* [ %37, %39 ], [ %30, %32 ], !dbg !326
  call void @llvm.dbg.value(metadata i8* %44, metadata !223, metadata !DIExpression()), !dbg !230
  call void @llvm.dbg.value(metadata i32 17, metadata !228, metadata !DIExpression()), !dbg !230
  call void @llvm.dbg.value(metadata %struct.hdr_cursor* undef, metadata !327, metadata !DIExpression()) #4, !dbg !337
  call void @llvm.dbg.value(metadata i8* %6, metadata !333, metadata !DIExpression()) #4, !dbg !337
  call void @llvm.dbg.value(metadata %struct.udphdr** undef, metadata !334, metadata !DIExpression()) #4, !dbg !337
  call void @llvm.dbg.value(metadata i8* %44, metadata !336, metadata !DIExpression()) #4, !dbg !337
  %45 = getelementptr i8, i8* %44, i64 8, !dbg !341
  %46 = icmp ugt i8* %45, %6, !dbg !343
  br i1 %46, label %66, label %47, !dbg !344

47:                                               ; preds = %43
  call void @llvm.dbg.value(metadata i8* %44, metadata !336, metadata !DIExpression()) #4, !dbg !337
  call void @llvm.dbg.value(metadata i8* %45, metadata !223, metadata !DIExpression()), !dbg !230
  %48 = getelementptr inbounds i8, i8* %44, i64 4, !dbg !345
  %49 = bitcast i8* %48 to i16*, !dbg !345
  %50 = load i16, i16* %49, align 2, !dbg !345, !tbaa !346
  %51 = tail call i16 @llvm.bswap.i16(i16 %50) #4, !dbg !345
  call void @llvm.dbg.value(metadata i16 %51, metadata !335, metadata !DIExpression(DW_OP_LLVM_convert, 16, DW_ATE_unsigned, DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_constu, 8, DW_OP_minus, DW_OP_stack_value)) #4, !dbg !337
  %52 = icmp ult i16 %51, 8, !dbg !348
  br i1 %52, label %66, label %53, !dbg !350

53:                                               ; preds = %47
  call void @llvm.dbg.value(metadata i16 %51, metadata !335, metadata !DIExpression(DW_OP_LLVM_convert, 16, DW_ATE_unsigned, DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_constu, 8, DW_OP_minus, DW_OP_stack_value)) #4, !dbg !337
  call void @llvm.dbg.value(metadata i16 %51, metadata !335, metadata !DIExpression(DW_OP_LLVM_convert, 16, DW_ATE_unsigned, DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_constu, 8, DW_OP_minus, DW_OP_stack_value)) #4, !dbg !337
  call void @llvm.dbg.value(metadata i16 %51, metadata !229, metadata !DIExpression(DW_OP_LLVM_convert, 16, DW_ATE_unsigned, DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_constu, 8, DW_OP_minus, DW_OP_stack_value)), !dbg !230
  call void @llvm.dbg.value(metadata i8* %44, metadata !214, metadata !DIExpression()), !dbg !230
  %54 = getelementptr inbounds i8, i8* %44, i64 2, !dbg !351
  %55 = bitcast i8* %54 to i16*, !dbg !351
  %56 = load i16, i16* %55, align 2, !dbg !351, !tbaa !353
  %57 = icmp eq i16 %56, 13568, !dbg !354
  br i1 %57, label %58, label %66, !dbg !355

58:                                               ; preds = %53
  call void @llvm.dbg.value(metadata i32* %2, metadata !128, metadata !DIExpression(DW_OP_deref)), !dbg !230
  %59 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i8* noundef bitcast (%struct.anon.5* @xsks_map to i8*), i8* noundef nonnull %11) #4, !dbg !356
  %60 = icmp eq i8* %59, null, !dbg !356
  br i1 %60, label %66, label %61, !dbg !358

61:                                               ; preds = %58
  %62 = load i32, i32* %2, align 4, !dbg !359, !tbaa !247
  call void @llvm.dbg.value(metadata i32 %62, metadata !128, metadata !DIExpression()), !dbg !230
  %63 = sext i32 %62 to i64, !dbg !359
  %64 = call i64 inttoptr (i64 51 to i64 (i8*, i64, i64)*)(i8* noundef bitcast (%struct.anon.5* @xsks_map to i8*), i64 noundef %63, i64 noundef 0) #4, !dbg !360
  %65 = trunc i64 %64 to i32, !dbg !360
  br label %66, !dbg !361

66:                                               ; preds = %47, %43, %36, %28, %23, %20, %1, %58, %53, %16, %39, %32, %61
  %67 = phi i32 [ %65, %61 ], [ 2, %32 ], [ 2, %39 ], [ 2, %16 ], [ 2, %53 ], [ 2, %58 ], [ 2, %1 ], [ 2, %20 ], [ 2, %23 ], [ 2, %28 ], [ 2, %36 ], [ 2, %43 ], [ 2, %47 ], !dbg !230
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %11) #4, !dbg !362
  ret i32 %67, !dbg !362
}

; Function Attrs: argmemonly mustprogress nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg, i8* nocapture) #1

; Function Attrs: argmemonly mustprogress nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg, i8* nocapture) #1

; Function Attrs: mustprogress nofree nosync nounwind readnone speculatable willreturn
declare i16 @llvm.bswap.i16(i16) #2

; Function Attrs: nofree nosync nounwind readnone speculatable willreturn
declare void @llvm.dbg.value(metadata, metadata, metadata) #3

attributes #0 = { nounwind "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" }
attributes #1 = { argmemonly mustprogress nofree nosync nounwind willreturn }
attributes #2 = { mustprogress nofree nosync nounwind readnone speculatable willreturn }
attributes #3 = { nofree nosync nounwind readnone speculatable willreturn }
attributes #4 = { nounwind }

!llvm.dbg.cu = !{!2}
!llvm.module.flags = !{!107, !108, !109, !110}
!llvm.ident = !{!111}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "xsks_map", scope: !2, file: !3, line: 20, type: !92, isLocal: false, isDefinition: true)
!2 = distinct !DICompileUnit(language: DW_LANG_C99, file: !3, producer: "Ubuntu clang version 14.0.0-1ubuntu1.1", isOptimized: true, runtimeVersion: 0, emissionKind: FullDebug, enums: !4, retainedTypes: !45, globals: !51, splitDebugInlining: false, nameTableKind: None)
!3 = !DIFile(filename: "dns_filter_kern.c", directory: "/home/quantumbits2/Documents/Python/cs331_cn/project/xdp-tutorial/aaa1111111111", checksumkind: CSK_MD5, checksum: "398b77a93aafcf73def23567c02f689a")
!4 = !{!5, !37}
!5 = !DICompositeType(tag: DW_TAG_enumeration_type, file: !6, line: 28, baseType: !7, size: 32, elements: !8)
!6 = !DIFile(filename: "/usr/include/linux/in.h", directory: "", checksumkind: CSK_MD5, checksum: "078a32220dc819f6a7e2ea3cecc4e133")
!7 = !DIBasicType(name: "unsigned int", size: 32, encoding: DW_ATE_unsigned)
!8 = !{!9, !10, !11, !12, !13, !14, !15, !16, !17, !18, !19, !20, !21, !22, !23, !24, !25, !26, !27, !28, !29, !30, !31, !32, !33, !34, !35, !36}
!9 = !DIEnumerator(name: "IPPROTO_IP", value: 0)
!10 = !DIEnumerator(name: "IPPROTO_ICMP", value: 1)
!11 = !DIEnumerator(name: "IPPROTO_IGMP", value: 2)
!12 = !DIEnumerator(name: "IPPROTO_IPIP", value: 4)
!13 = !DIEnumerator(name: "IPPROTO_TCP", value: 6)
!14 = !DIEnumerator(name: "IPPROTO_EGP", value: 8)
!15 = !DIEnumerator(name: "IPPROTO_PUP", value: 12)
!16 = !DIEnumerator(name: "IPPROTO_UDP", value: 17)
!17 = !DIEnumerator(name: "IPPROTO_IDP", value: 22)
!18 = !DIEnumerator(name: "IPPROTO_TP", value: 29)
!19 = !DIEnumerator(name: "IPPROTO_DCCP", value: 33)
!20 = !DIEnumerator(name: "IPPROTO_IPV6", value: 41)
!21 = !DIEnumerator(name: "IPPROTO_RSVP", value: 46)
!22 = !DIEnumerator(name: "IPPROTO_GRE", value: 47)
!23 = !DIEnumerator(name: "IPPROTO_ESP", value: 50)
!24 = !DIEnumerator(name: "IPPROTO_AH", value: 51)
!25 = !DIEnumerator(name: "IPPROTO_MTP", value: 92)
!26 = !DIEnumerator(name: "IPPROTO_BEETPH", value: 94)
!27 = !DIEnumerator(name: "IPPROTO_ENCAP", value: 98)
!28 = !DIEnumerator(name: "IPPROTO_PIM", value: 103)
!29 = !DIEnumerator(name: "IPPROTO_COMP", value: 108)
!30 = !DIEnumerator(name: "IPPROTO_SCTP", value: 132)
!31 = !DIEnumerator(name: "IPPROTO_UDPLITE", value: 136)
!32 = !DIEnumerator(name: "IPPROTO_MPLS", value: 137)
!33 = !DIEnumerator(name: "IPPROTO_ETHERNET", value: 143)
!34 = !DIEnumerator(name: "IPPROTO_RAW", value: 255)
!35 = !DIEnumerator(name: "IPPROTO_MPTCP", value: 262)
!36 = !DIEnumerator(name: "IPPROTO_MAX", value: 263)
!37 = !DICompositeType(tag: DW_TAG_enumeration_type, name: "xdp_action", file: !38, line: 5447, baseType: !7, size: 32, elements: !39)
!38 = !DIFile(filename: "/usr/include/linux/bpf.h", directory: "", checksumkind: CSK_MD5, checksum: "e35b163ac757a706afe87c4e3c9d01d2")
!39 = !{!40, !41, !42, !43, !44}
!40 = !DIEnumerator(name: "XDP_ABORTED", value: 0)
!41 = !DIEnumerator(name: "XDP_DROP", value: 1)
!42 = !DIEnumerator(name: "XDP_PASS", value: 2)
!43 = !DIEnumerator(name: "XDP_TX", value: 3)
!44 = !DIEnumerator(name: "XDP_REDIRECT", value: 4)
!45 = !{!46, !47, !48}
!46 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: null, size: 64)
!47 = !DIBasicType(name: "long", size: 64, encoding: DW_ATE_signed)
!48 = !DIDerivedType(tag: DW_TAG_typedef, name: "__u16", file: !49, line: 24, baseType: !50)
!49 = !DIFile(filename: "/usr/include/asm-generic/int-ll64.h", directory: "", checksumkind: CSK_MD5, checksum: "b810f270733e106319b67ef512c6246e")
!50 = !DIBasicType(name: "unsigned short", size: 16, encoding: DW_ATE_unsigned)
!51 = !{!52, !0, !58, !77, !85}
!52 = !DIGlobalVariableExpression(var: !53, expr: !DIExpression())
!53 = distinct !DIGlobalVariable(name: "_license", scope: !2, file: !3, line: 183, type: !54, isLocal: false, isDefinition: true)
!54 = !DICompositeType(tag: DW_TAG_array_type, baseType: !55, size: 32, elements: !56)
!55 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!56 = !{!57}
!57 = !DISubrange(count: 4)
!58 = !DIGlobalVariableExpression(var: !59, expr: !DIExpression())
!59 = distinct !DIGlobalVariable(name: "xdp_stats_map", scope: !2, file: !3, line: 27, type: !60, isLocal: false, isDefinition: true)
!60 = distinct !DICompositeType(tag: DW_TAG_structure_type, file: !3, line: 22, size: 256, elements: !61)
!61 = !{!62, !68, !71, !72}
!62 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !60, file: !3, line: 23, baseType: !63, size: 64)
!63 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !64, size: 64)
!64 = !DICompositeType(tag: DW_TAG_array_type, baseType: !65, size: 192, elements: !66)
!65 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!66 = !{!67}
!67 = !DISubrange(count: 6)
!68 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !60, file: !3, line: 24, baseType: !69, size: 64, offset: 64)
!69 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !70, size: 64)
!70 = !DIDerivedType(tag: DW_TAG_typedef, name: "__u32", file: !49, line: 27, baseType: !7)
!71 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !60, file: !3, line: 25, baseType: !69, size: 64, offset: 128)
!72 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !60, file: !3, line: 26, baseType: !73, size: 64, offset: 192)
!73 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !74, size: 64)
!74 = !DICompositeType(tag: DW_TAG_array_type, baseType: !65, size: 2048, elements: !75)
!75 = !{!76}
!76 = !DISubrange(count: 64)
!77 = !DIGlobalVariableExpression(var: !78, expr: !DIExpression())
!78 = distinct !DIGlobalVariable(name: "bpf_map_lookup_elem", scope: !2, file: !79, line: 56, type: !80, isLocal: true, isDefinition: true)
!79 = !DIFile(filename: "../lib/install/include/bpf/bpf_helper_defs.h", directory: "/home/quantumbits2/Documents/Python/cs331_cn/project/xdp-tutorial/aaa1111111111", checksumkind: CSK_MD5, checksum: "7422ca06c9dc86eba2f268a57d8acf2f")
!80 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !81, size: 64)
!81 = !DISubroutineType(types: !82)
!82 = !{!46, !46, !83}
!83 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !84, size: 64)
!84 = !DIDerivedType(tag: DW_TAG_const_type, baseType: null)
!85 = !DIGlobalVariableExpression(var: !86, expr: !DIExpression())
!86 = distinct !DIGlobalVariable(name: "bpf_redirect_map", scope: !2, file: !79, line: 1323, type: !87, isLocal: true, isDefinition: true)
!87 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !88, size: 64)
!88 = !DISubroutineType(types: !89)
!89 = !{!47, !46, !90, !90}
!90 = !DIDerivedType(tag: DW_TAG_typedef, name: "__u64", file: !49, line: 31, baseType: !91)
!91 = !DIBasicType(name: "unsigned long long", size: 64, encoding: DW_ATE_unsigned)
!92 = distinct !DICompositeType(tag: DW_TAG_structure_type, file: !3, line: 14, size: 320, elements: !93)
!93 = !{!94, !99, !100, !101, !102}
!94 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !92, file: !3, line: 15, baseType: !95, size: 64)
!95 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !96, size: 64)
!96 = !DICompositeType(tag: DW_TAG_array_type, baseType: !65, size: 544, elements: !97)
!97 = !{!98}
!98 = !DISubrange(count: 17)
!99 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !92, file: !3, line: 16, baseType: !69, size: 64, offset: 64)
!100 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !92, file: !3, line: 17, baseType: !69, size: 64, offset: 128)
!101 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !92, file: !3, line: 18, baseType: !73, size: 64, offset: 192)
!102 = !DIDerivedType(tag: DW_TAG_member, name: "pinning", scope: !92, file: !3, line: 19, baseType: !103, size: 64, offset: 256)
!103 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !104, size: 64)
!104 = !DICompositeType(tag: DW_TAG_array_type, baseType: !65, size: 32, elements: !105)
!105 = !{!106}
!106 = !DISubrange(count: 1)
!107 = !{i32 7, !"Dwarf Version", i32 5}
!108 = !{i32 2, !"Debug Info Version", i32 3}
!109 = !{i32 1, !"wchar_size", i32 4}
!110 = !{i32 7, !"frame-pointer", i32 2}
!111 = !{!"Ubuntu clang version 14.0.0-1ubuntu1.1"}
!112 = distinct !DISubprogram(name: "xdp_dns_filter_func", scope: !3, file: !3, line: 131, type: !113, scopeLine: 132, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !124)
!113 = !DISubroutineType(types: !114)
!114 = !{!65, !115}
!115 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !116, size: 64)
!116 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "xdp_md", file: !38, line: 5458, size: 192, elements: !117)
!117 = !{!118, !119, !120, !121, !122, !123}
!118 = !DIDerivedType(tag: DW_TAG_member, name: "data", scope: !116, file: !38, line: 5459, baseType: !70, size: 32)
!119 = !DIDerivedType(tag: DW_TAG_member, name: "data_end", scope: !116, file: !38, line: 5460, baseType: !70, size: 32, offset: 32)
!120 = !DIDerivedType(tag: DW_TAG_member, name: "data_meta", scope: !116, file: !38, line: 5461, baseType: !70, size: 32, offset: 64)
!121 = !DIDerivedType(tag: DW_TAG_member, name: "ingress_ifindex", scope: !116, file: !38, line: 5463, baseType: !70, size: 32, offset: 96)
!122 = !DIDerivedType(tag: DW_TAG_member, name: "rx_queue_index", scope: !116, file: !38, line: 5464, baseType: !70, size: 32, offset: 128)
!123 = !DIDerivedType(tag: DW_TAG_member, name: "egress_ifindex", scope: !116, file: !38, line: 5466, baseType: !70, size: 32, offset: 160)
!124 = !{!125, !126, !127, !128, !129, !141, !171, !214, !223, !227, !228, !229}
!125 = !DILocalVariable(name: "ctx", arg: 1, scope: !112, file: !3, line: 131, type: !115)
!126 = !DILocalVariable(name: "data_end", scope: !112, file: !3, line: 133, type: !46)
!127 = !DILocalVariable(name: "data", scope: !112, file: !3, line: 134, type: !46)
!128 = !DILocalVariable(name: "index", scope: !112, file: !3, line: 135, type: !65)
!129 = !DILocalVariable(name: "eth", scope: !112, file: !3, line: 137, type: !130)
!130 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !131, size: 64)
!131 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "ethhdr", file: !132, line: 168, size: 112, elements: !133)
!132 = !DIFile(filename: "/usr/include/linux/if_ether.h", directory: "", checksumkind: CSK_MD5, checksum: "ab0320da726e75d904811ce344979934")
!133 = !{!134, !137, !138}
!134 = !DIDerivedType(tag: DW_TAG_member, name: "h_dest", scope: !131, file: !132, line: 169, baseType: !135, size: 48)
!135 = !DICompositeType(tag: DW_TAG_array_type, baseType: !136, size: 48, elements: !66)
!136 = !DIBasicType(name: "unsigned char", size: 8, encoding: DW_ATE_unsigned_char)
!137 = !DIDerivedType(tag: DW_TAG_member, name: "h_source", scope: !131, file: !132, line: 170, baseType: !135, size: 48, offset: 48)
!138 = !DIDerivedType(tag: DW_TAG_member, name: "h_proto", scope: !131, file: !132, line: 171, baseType: !139, size: 16, offset: 96)
!139 = !DIDerivedType(tag: DW_TAG_typedef, name: "__be16", file: !140, line: 25, baseType: !48)
!140 = !DIFile(filename: "/usr/include/linux/types.h", directory: "", checksumkind: CSK_MD5, checksum: "52ec79a38e49ac7d1dc9e146ba88a7b1")
!141 = !DILocalVariable(name: "iphdr", scope: !112, file: !3, line: 138, type: !142)
!142 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !143, size: 64)
!143 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "iphdr", file: !144, line: 87, size: 160, elements: !145)
!144 = !DIFile(filename: "/usr/include/linux/ip.h", directory: "", checksumkind: CSK_MD5, checksum: "042b09a58768855e3578a0a8eba49be7")
!145 = !{!146, !148, !149, !150, !151, !152, !153, !154, !155, !157}
!146 = !DIDerivedType(tag: DW_TAG_member, name: "ihl", scope: !143, file: !144, line: 89, baseType: !147, size: 4, flags: DIFlagBitField, extraData: i64 0)
!147 = !DIDerivedType(tag: DW_TAG_typedef, name: "__u8", file: !49, line: 21, baseType: !136)
!148 = !DIDerivedType(tag: DW_TAG_member, name: "version", scope: !143, file: !144, line: 90, baseType: !147, size: 4, offset: 4, flags: DIFlagBitField, extraData: i64 0)
!149 = !DIDerivedType(tag: DW_TAG_member, name: "tos", scope: !143, file: !144, line: 97, baseType: !147, size: 8, offset: 8)
!150 = !DIDerivedType(tag: DW_TAG_member, name: "tot_len", scope: !143, file: !144, line: 98, baseType: !139, size: 16, offset: 16)
!151 = !DIDerivedType(tag: DW_TAG_member, name: "id", scope: !143, file: !144, line: 99, baseType: !139, size: 16, offset: 32)
!152 = !DIDerivedType(tag: DW_TAG_member, name: "frag_off", scope: !143, file: !144, line: 100, baseType: !139, size: 16, offset: 48)
!153 = !DIDerivedType(tag: DW_TAG_member, name: "ttl", scope: !143, file: !144, line: 101, baseType: !147, size: 8, offset: 64)
!154 = !DIDerivedType(tag: DW_TAG_member, name: "protocol", scope: !143, file: !144, line: 102, baseType: !147, size: 8, offset: 72)
!155 = !DIDerivedType(tag: DW_TAG_member, name: "check", scope: !143, file: !144, line: 103, baseType: !156, size: 16, offset: 80)
!156 = !DIDerivedType(tag: DW_TAG_typedef, name: "__sum16", file: !140, line: 31, baseType: !48)
!157 = !DIDerivedType(tag: DW_TAG_member, scope: !143, file: !144, line: 104, baseType: !158, size: 64, offset: 96)
!158 = distinct !DICompositeType(tag: DW_TAG_union_type, scope: !143, file: !144, line: 104, size: 64, elements: !159)
!159 = !{!160, !166}
!160 = !DIDerivedType(tag: DW_TAG_member, scope: !158, file: !144, line: 104, baseType: !161, size: 64)
!161 = distinct !DICompositeType(tag: DW_TAG_structure_type, scope: !158, file: !144, line: 104, size: 64, elements: !162)
!162 = !{!163, !165}
!163 = !DIDerivedType(tag: DW_TAG_member, name: "saddr", scope: !161, file: !144, line: 104, baseType: !164, size: 32)
!164 = !DIDerivedType(tag: DW_TAG_typedef, name: "__be32", file: !140, line: 27, baseType: !70)
!165 = !DIDerivedType(tag: DW_TAG_member, name: "daddr", scope: !161, file: !144, line: 104, baseType: !164, size: 32, offset: 32)
!166 = !DIDerivedType(tag: DW_TAG_member, name: "addrs", scope: !158, file: !144, line: 104, baseType: !167, size: 64)
!167 = distinct !DICompositeType(tag: DW_TAG_structure_type, scope: !158, file: !144, line: 104, size: 64, elements: !168)
!168 = !{!169, !170}
!169 = !DIDerivedType(tag: DW_TAG_member, name: "saddr", scope: !167, file: !144, line: 104, baseType: !164, size: 32)
!170 = !DIDerivedType(tag: DW_TAG_member, name: "daddr", scope: !167, file: !144, line: 104, baseType: !164, size: 32, offset: 32)
!171 = !DILocalVariable(name: "ipv6hdr", scope: !112, file: !3, line: 139, type: !172)
!172 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !173, size: 64)
!173 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "ipv6hdr", file: !174, line: 118, size: 320, elements: !175)
!174 = !DIFile(filename: "/usr/include/linux/ipv6.h", directory: "", checksumkind: CSK_MD5, checksum: "9926d49458ea1e0cc4651362e733e03e")
!175 = !{!176, !177, !178, !182, !183, !184, !185}
!176 = !DIDerivedType(tag: DW_TAG_member, name: "priority", scope: !173, file: !174, line: 120, baseType: !147, size: 4, flags: DIFlagBitField, extraData: i64 0)
!177 = !DIDerivedType(tag: DW_TAG_member, name: "version", scope: !173, file: !174, line: 121, baseType: !147, size: 4, offset: 4, flags: DIFlagBitField, extraData: i64 0)
!178 = !DIDerivedType(tag: DW_TAG_member, name: "flow_lbl", scope: !173, file: !174, line: 128, baseType: !179, size: 24, offset: 8)
!179 = !DICompositeType(tag: DW_TAG_array_type, baseType: !147, size: 24, elements: !180)
!180 = !{!181}
!181 = !DISubrange(count: 3)
!182 = !DIDerivedType(tag: DW_TAG_member, name: "payload_len", scope: !173, file: !174, line: 130, baseType: !139, size: 16, offset: 32)
!183 = !DIDerivedType(tag: DW_TAG_member, name: "nexthdr", scope: !173, file: !174, line: 131, baseType: !147, size: 8, offset: 48)
!184 = !DIDerivedType(tag: DW_TAG_member, name: "hop_limit", scope: !173, file: !174, line: 132, baseType: !147, size: 8, offset: 56)
!185 = !DIDerivedType(tag: DW_TAG_member, scope: !173, file: !174, line: 134, baseType: !186, size: 256, offset: 64)
!186 = distinct !DICompositeType(tag: DW_TAG_union_type, scope: !173, file: !174, line: 134, size: 256, elements: !187)
!187 = !{!188, !209}
!188 = !DIDerivedType(tag: DW_TAG_member, scope: !186, file: !174, line: 134, baseType: !189, size: 256)
!189 = distinct !DICompositeType(tag: DW_TAG_structure_type, scope: !186, file: !174, line: 134, size: 256, elements: !190)
!190 = !{!191, !208}
!191 = !DIDerivedType(tag: DW_TAG_member, name: "saddr", scope: !189, file: !174, line: 134, baseType: !192, size: 128)
!192 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "in6_addr", file: !193, line: 33, size: 128, elements: !194)
!193 = !DIFile(filename: "/usr/include/linux/in6.h", directory: "", checksumkind: CSK_MD5, checksum: "fca1889f0274df066e49cf4d8db8011e")
!194 = !{!195}
!195 = !DIDerivedType(tag: DW_TAG_member, name: "in6_u", scope: !192, file: !193, line: 40, baseType: !196, size: 128)
!196 = distinct !DICompositeType(tag: DW_TAG_union_type, scope: !192, file: !193, line: 34, size: 128, elements: !197)
!197 = !{!198, !202, !206}
!198 = !DIDerivedType(tag: DW_TAG_member, name: "u6_addr8", scope: !196, file: !193, line: 35, baseType: !199, size: 128)
!199 = !DICompositeType(tag: DW_TAG_array_type, baseType: !147, size: 128, elements: !200)
!200 = !{!201}
!201 = !DISubrange(count: 16)
!202 = !DIDerivedType(tag: DW_TAG_member, name: "u6_addr16", scope: !196, file: !193, line: 37, baseType: !203, size: 128)
!203 = !DICompositeType(tag: DW_TAG_array_type, baseType: !139, size: 128, elements: !204)
!204 = !{!205}
!205 = !DISubrange(count: 8)
!206 = !DIDerivedType(tag: DW_TAG_member, name: "u6_addr32", scope: !196, file: !193, line: 38, baseType: !207, size: 128)
!207 = !DICompositeType(tag: DW_TAG_array_type, baseType: !164, size: 128, elements: !56)
!208 = !DIDerivedType(tag: DW_TAG_member, name: "daddr", scope: !189, file: !174, line: 134, baseType: !192, size: 128, offset: 128)
!209 = !DIDerivedType(tag: DW_TAG_member, name: "addrs", scope: !186, file: !174, line: 134, baseType: !210, size: 256)
!210 = distinct !DICompositeType(tag: DW_TAG_structure_type, scope: !186, file: !174, line: 134, size: 256, elements: !211)
!211 = !{!212, !213}
!212 = !DIDerivedType(tag: DW_TAG_member, name: "saddr", scope: !210, file: !174, line: 134, baseType: !192, size: 128)
!213 = !DIDerivedType(tag: DW_TAG_member, name: "daddr", scope: !210, file: !174, line: 134, baseType: !192, size: 128, offset: 128)
!214 = !DILocalVariable(name: "udphdr", scope: !112, file: !3, line: 140, type: !215)
!215 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !216, size: 64)
!216 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "udphdr", file: !217, line: 23, size: 64, elements: !218)
!217 = !DIFile(filename: "/usr/include/linux/udp.h", directory: "", checksumkind: CSK_MD5, checksum: "53c0d42e1bf6d93b39151764be2d20fb")
!218 = !{!219, !220, !221, !222}
!219 = !DIDerivedType(tag: DW_TAG_member, name: "source", scope: !216, file: !217, line: 24, baseType: !139, size: 16)
!220 = !DIDerivedType(tag: DW_TAG_member, name: "dest", scope: !216, file: !217, line: 25, baseType: !139, size: 16, offset: 16)
!221 = !DIDerivedType(tag: DW_TAG_member, name: "len", scope: !216, file: !217, line: 26, baseType: !139, size: 16, offset: 32)
!222 = !DIDerivedType(tag: DW_TAG_member, name: "check", scope: !216, file: !217, line: 27, baseType: !156, size: 16, offset: 48)
!223 = !DILocalVariable(name: "nh", scope: !112, file: !3, line: 142, type: !224)
!224 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "hdr_cursor", file: !3, line: 30, size: 64, elements: !225)
!225 = !{!226}
!226 = !DIDerivedType(tag: DW_TAG_member, name: "pos", scope: !224, file: !3, line: 31, baseType: !46, size: 64)
!227 = !DILocalVariable(name: "eth_type", scope: !112, file: !3, line: 143, type: !65)
!228 = !DILocalVariable(name: "ip_type", scope: !112, file: !3, line: 144, type: !65)
!229 = !DILocalVariable(name: "udp_len", scope: !112, file: !3, line: 145, type: !65)
!230 = !DILocation(line: 0, scope: !112)
!231 = !DILocation(line: 133, column: 41, scope: !112)
!232 = !{!233, !234, i64 4}
!233 = !{!"xdp_md", !234, i64 0, !234, i64 4, !234, i64 8, !234, i64 12, !234, i64 16, !234, i64 20}
!234 = !{!"int", !235, i64 0}
!235 = !{!"omnipotent char", !236, i64 0}
!236 = !{!"Simple C/C++ TBAA"}
!237 = !DILocation(line: 133, column: 30, scope: !112)
!238 = !DILocation(line: 133, column: 22, scope: !112)
!239 = !DILocation(line: 134, column: 37, scope: !112)
!240 = !{!233, !234, i64 0}
!241 = !DILocation(line: 134, column: 26, scope: !112)
!242 = !DILocation(line: 134, column: 18, scope: !112)
!243 = !DILocation(line: 135, column: 5, scope: !112)
!244 = !DILocation(line: 135, column: 22, scope: !112)
!245 = !{!233, !234, i64 16}
!246 = !DILocation(line: 135, column: 9, scope: !112)
!247 = !{!234, !234, i64 0}
!248 = !DILocalVariable(name: "nh", arg: 1, scope: !249, file: !3, line: 42, type: !252)
!249 = distinct !DISubprogram(name: "parse_ethhdr", scope: !3, file: !3, line: 42, type: !250, scopeLine: 45, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !254)
!250 = !DISubroutineType(types: !251)
!251 = !{!65, !252, !46, !253}
!252 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !224, size: 64)
!253 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !130, size: 64)
!254 = !{!248, !255, !256, !257, !258}
!255 = !DILocalVariable(name: "data_end", arg: 2, scope: !249, file: !3, line: 43, type: !46)
!256 = !DILocalVariable(name: "ethhdr", arg: 3, scope: !249, file: !3, line: 44, type: !253)
!257 = !DILocalVariable(name: "eth", scope: !249, file: !3, line: 46, type: !130)
!258 = !DILocalVariable(name: "hdrsize", scope: !249, file: !3, line: 47, type: !65)
!259 = !DILocation(line: 0, scope: !249, inlinedAt: !260)
!260 = distinct !DILocation(line: 151, column: 16, scope: !112)
!261 = !DILocation(line: 50, column: 24, scope: !262, inlinedAt: !260)
!262 = distinct !DILexicalBlock(scope: !249, file: !3, line: 50, column: 9)
!263 = !DILocation(line: 50, column: 34, scope: !262, inlinedAt: !260)
!264 = !DILocation(line: 50, column: 9, scope: !249, inlinedAt: !260)
!265 = !DILocation(line: 56, column: 17, scope: !249, inlinedAt: !260)
!266 = !{!267, !268, i64 12}
!267 = !{!"ethhdr", !235, i64 0, !235, i64 6, !268, i64 12}
!268 = !{!"short", !235, i64 0}
!269 = !DILocation(line: 152, column: 6, scope: !112)
!270 = !DILocalVariable(name: "nh", arg: 1, scope: !271, file: !3, line: 81, type: !252)
!271 = distinct !DISubprogram(name: "parse_iphdr", scope: !3, file: !3, line: 81, type: !272, scopeLine: 84, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !275)
!272 = !DISubroutineType(types: !273)
!273 = !{!65, !252, !46, !274}
!274 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !142, size: 64)
!275 = !{!270, !276, !277, !278, !279}
!276 = !DILocalVariable(name: "data_end", arg: 2, scope: !271, file: !3, line: 82, type: !46)
!277 = !DILocalVariable(name: "iphdr", arg: 3, scope: !271, file: !3, line: 83, type: !274)
!278 = !DILocalVariable(name: "iph", scope: !271, file: !3, line: 85, type: !142)
!279 = !DILocalVariable(name: "hdrsize", scope: !271, file: !3, line: 86, type: !65)
!280 = !DILocation(line: 0, scope: !271, inlinedAt: !281)
!281 = distinct !DILocation(line: 153, column: 13, scope: !282)
!282 = distinct !DILexicalBlock(scope: !283, file: !3, line: 152, column: 39)
!283 = distinct !DILexicalBlock(scope: !112, file: !3, line: 152, column: 6)
!284 = !DILocation(line: 88, column: 13, scope: !285, inlinedAt: !281)
!285 = distinct !DILexicalBlock(scope: !271, file: !3, line: 88, column: 9)
!286 = !DILocation(line: 88, column: 17, scope: !285, inlinedAt: !281)
!287 = !DILocation(line: 88, column: 9, scope: !271, inlinedAt: !281)
!288 = !DILocation(line: 91, column: 20, scope: !271, inlinedAt: !281)
!289 = !DILocation(line: 91, column: 24, scope: !271, inlinedAt: !281)
!290 = !DILocation(line: 93, column: 16, scope: !291, inlinedAt: !281)
!291 = distinct !DILexicalBlock(scope: !271, file: !3, line: 93, column: 8)
!292 = !DILocation(line: 93, column: 8, scope: !271, inlinedAt: !281)
!293 = !DILocation(line: 97, column: 17, scope: !294, inlinedAt: !281)
!294 = distinct !DILexicalBlock(scope: !271, file: !3, line: 97, column: 9)
!295 = !DILocation(line: 97, column: 27, scope: !294, inlinedAt: !281)
!296 = !DILocation(line: 97, column: 9, scope: !271, inlinedAt: !281)
!297 = !DILocation(line: 103, column: 17, scope: !271, inlinedAt: !281)
!298 = !{!299, !235, i64 9}
!299 = !{!"iphdr", !235, i64 0, !235, i64 0, !235, i64 1, !268, i64 2, !268, i64 4, !268, i64 6, !235, i64 8, !235, i64 9, !268, i64 10, !235, i64 12}
!300 = !DILocation(line: 154, column: 15, scope: !301)
!301 = distinct !DILexicalBlock(scope: !282, file: !3, line: 154, column: 7)
!302 = !DILocation(line: 154, column: 7, scope: !282)
!303 = !DILocalVariable(name: "nh", arg: 1, scope: !304, file: !3, line: 60, type: !252)
!304 = distinct !DISubprogram(name: "parse_ip6hdr", scope: !3, file: !3, line: 60, type: !305, scopeLine: 63, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !308)
!305 = !DISubroutineType(types: !306)
!306 = !{!65, !252, !46, !307}
!307 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !172, size: 64)
!308 = !{!303, !309, !310, !311}
!309 = !DILocalVariable(name: "data_end", arg: 2, scope: !304, file: !3, line: 61, type: !46)
!310 = !DILocalVariable(name: "ip6hdr", arg: 3, scope: !304, file: !3, line: 62, type: !307)
!311 = !DILocalVariable(name: "ip6h", scope: !304, file: !3, line: 64, type: !172)
!312 = !DILocation(line: 0, scope: !304, inlinedAt: !313)
!313 = distinct !DILocation(line: 157, column: 13, scope: !314)
!314 = distinct !DILexicalBlock(scope: !315, file: !3, line: 156, column: 48)
!315 = distinct !DILexicalBlock(scope: !283, file: !3, line: 156, column: 13)
!316 = !DILocation(line: 70, column: 20, scope: !317, inlinedAt: !313)
!317 = distinct !DILexicalBlock(scope: !304, file: !3, line: 70, column: 8)
!318 = !DILocation(line: 70, column: 36, scope: !317, inlinedAt: !313)
!319 = !DILocation(line: 70, column: 8, scope: !304, inlinedAt: !313)
!320 = !DILocation(line: 77, column: 18, scope: !304, inlinedAt: !313)
!321 = !{!322, !235, i64 6}
!322 = !{!"ipv6hdr", !235, i64 0, !235, i64 0, !235, i64 1, !268, i64 4, !235, i64 6, !235, i64 7, !235, i64 8}
!323 = !DILocation(line: 158, column: 15, scope: !324)
!324 = distinct !DILexicalBlock(scope: !314, file: !3, line: 158, column: 7)
!325 = !DILocation(line: 158, column: 7, scope: !314)
!326 = !DILocation(line: 148, column: 12, scope: !112)
!327 = !DILocalVariable(name: "nh", arg: 1, scope: !328, file: !3, line: 109, type: !252)
!328 = distinct !DISubprogram(name: "parse_udphdr", scope: !3, file: !3, line: 109, type: !329, scopeLine: 112, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !332)
!329 = !DISubroutineType(types: !330)
!330 = !{!65, !252, !46, !331}
!331 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !215, size: 64)
!332 = !{!327, !333, !334, !335, !336}
!333 = !DILocalVariable(name: "data_end", arg: 2, scope: !328, file: !3, line: 110, type: !46)
!334 = !DILocalVariable(name: "udphdr", arg: 3, scope: !328, file: !3, line: 111, type: !331)
!335 = !DILocalVariable(name: "len", scope: !328, file: !3, line: 113, type: !65)
!336 = !DILocalVariable(name: "h", scope: !328, file: !3, line: 114, type: !215)
!337 = !DILocation(line: 0, scope: !328, inlinedAt: !338)
!338 = distinct !DILocation(line: 166, column: 19, scope: !339)
!339 = distinct !DILexicalBlock(scope: !340, file: !3, line: 165, column: 33)
!340 = distinct !DILexicalBlock(scope: !112, file: !3, line: 165, column: 9)
!341 = !DILocation(line: 116, column: 18, scope: !342, inlinedAt: !338)
!342 = distinct !DILexicalBlock(scope: !328, file: !3, line: 116, column: 9)
!343 = !DILocation(line: 116, column: 31, scope: !342, inlinedAt: !338)
!344 = !DILocation(line: 116, column: 9, scope: !328, inlinedAt: !338)
!345 = !DILocation(line: 122, column: 11, scope: !328, inlinedAt: !338)
!346 = !{!347, !268, i64 4}
!347 = !{!"udphdr", !268, i64 0, !268, i64 2, !268, i64 4, !268, i64 6}
!348 = !DILocation(line: 123, column: 13, scope: !349, inlinedAt: !338)
!349 = distinct !DILexicalBlock(scope: !328, file: !3, line: 123, column: 9)
!350 = !DILocation(line: 123, column: 9, scope: !328, inlinedAt: !338)
!351 = !DILocation(line: 171, column: 21, scope: !352)
!352 = distinct !DILexicalBlock(scope: !339, file: !3, line: 171, column: 13)
!353 = !{!347, !268, i64 2}
!354 = !DILocation(line: 171, column: 26, scope: !352)
!355 = !DILocation(line: 171, column: 13, scope: !339)
!356 = !DILocation(line: 176, column: 13, scope: !357)
!357 = distinct !DILexicalBlock(scope: !339, file: !3, line: 176, column: 13)
!358 = !DILocation(line: 176, column: 13, scope: !339)
!359 = !DILocation(line: 177, column: 48, scope: !357)
!360 = !DILocation(line: 177, column: 20, scope: !357)
!361 = !DILocation(line: 177, column: 13, scope: !357)
!362 = !DILocation(line: 181, column: 1, scope: !112)
