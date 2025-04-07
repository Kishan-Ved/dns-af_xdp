; ModuleID = 'dns_filter_kern.c'
source_filename = "dns_filter_kern.c"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

%struct.anon.1 = type { [17 x i32]*, i32*, i32*, [64 x i32]*, [1 x i32]* }
%struct.xdp_md = type { i32, i32, i32, i32, i32, i32 }
%struct.ethhdr = type { [6 x i8], [6 x i8], i16 }
%struct.iphdr = type { i8, i8, i16, i16, i16, i8, i8, i16, %union.anon }
%union.anon = type { %struct.anon }
%struct.anon = type { i32, i32 }

@xsks_map = dso_local global %struct.anon.1 zeroinitializer, section ".maps", align 8, !dbg !0
@_license = dso_local global [4 x i8] c"GPL\00", section "license", align 1, !dbg !23
@llvm.compiler.used = appending global [3 x i8*] [i8* getelementptr inbounds ([4 x i8], [4 x i8]* @_license, i32 0, i32 0), i8* bitcast (i32 (%struct.xdp_md*)* @xdp_dns_filter_func to i8*), i8* bitcast (%struct.anon.1* @xsks_map to i8*)], section "llvm.metadata"

; Function Attrs: nounwind
define dso_local i32 @xdp_dns_filter_func(%struct.xdp_md* nocapture noundef readonly %0) #0 section "xdp_dns_filter" !dbg !71 {
  %2 = alloca i32, align 4
  call void @llvm.dbg.value(metadata %struct.xdp_md* %0, metadata !84, metadata !DIExpression()), !dbg !141
  %3 = getelementptr inbounds %struct.xdp_md, %struct.xdp_md* %0, i64 0, i32 1, !dbg !142
  %4 = load i32, i32* %3, align 4, !dbg !142, !tbaa !143
  %5 = zext i32 %4 to i64, !dbg !148
  %6 = inttoptr i64 %5 to i8*, !dbg !149
  call void @llvm.dbg.value(metadata i8* %6, metadata !85, metadata !DIExpression()), !dbg !141
  %7 = getelementptr inbounds %struct.xdp_md, %struct.xdp_md* %0, i64 0, i32 0, !dbg !150
  %8 = load i32, i32* %7, align 4, !dbg !150, !tbaa !151
  %9 = zext i32 %8 to i64, !dbg !152
  %10 = inttoptr i64 %9 to i8*, !dbg !153
  call void @llvm.dbg.value(metadata i8* %10, metadata !86, metadata !DIExpression()), !dbg !141
  %11 = bitcast i32* %2 to i8*, !dbg !154
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %11) #3, !dbg !154
  %12 = getelementptr inbounds %struct.xdp_md, %struct.xdp_md* %0, i64 0, i32 4, !dbg !155
  %13 = load i32, i32* %12, align 4, !dbg !155, !tbaa !156
  call void @llvm.dbg.value(metadata i32 %13, metadata !140, metadata !DIExpression()), !dbg !141
  store i32 %13, i32* %2, align 4, !dbg !157, !tbaa !158
  call void @llvm.dbg.value(metadata %struct.ethhdr** undef, metadata !87, metadata !DIExpression(DW_OP_deref)), !dbg !141
  call void @llvm.dbg.value(metadata i8** undef, metadata !159, metadata !DIExpression()) #3, !dbg !169
  call void @llvm.dbg.value(metadata i8* %6, metadata !166, metadata !DIExpression()) #3, !dbg !169
  call void @llvm.dbg.value(metadata %struct.ethhdr** undef, metadata !167, metadata !DIExpression()) #3, !dbg !169
  call void @llvm.dbg.value(metadata i8* %10, metadata !168, metadata !DIExpression()) #3, !dbg !169
  %14 = getelementptr i8, i8* %10, i64 14, !dbg !171
  %15 = icmp ugt i8* %14, %6, !dbg !173
  br i1 %15, label %55, label %16, !dbg !174

16:                                               ; preds = %1
  call void @llvm.dbg.value(metadata i8* %10, metadata !168, metadata !DIExpression()) #3, !dbg !169
  %17 = getelementptr inbounds i8, i8* %10, i64 12, !dbg !175
  %18 = bitcast i8* %17 to i16*, !dbg !175
  %19 = load i16, i16* %18, align 1, !dbg !175, !tbaa !176
  call void @llvm.dbg.value(metadata i16 undef, metadata !138, metadata !DIExpression(DW_OP_LLVM_convert, 16, DW_ATE_unsigned, DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !141
  %20 = icmp ne i16 %19, 2048
  %21 = getelementptr i8, i8* %10, i64 34
  %22 = icmp ugt i8* %21, %6
  %23 = select i1 %20, i1 true, i1 %22, !dbg !179
  call void @llvm.dbg.value(metadata %struct.iphdr** undef, metadata !99, metadata !DIExpression(DW_OP_deref)), !dbg !141
  call void @llvm.dbg.value(metadata i8** undef, metadata !180, metadata !DIExpression()), !dbg !189
  call void @llvm.dbg.value(metadata i8* %6, metadata !186, metadata !DIExpression()), !dbg !189
  call void @llvm.dbg.value(metadata %struct.iphdr** undef, metadata !187, metadata !DIExpression()), !dbg !189
  call void @llvm.dbg.value(metadata i8* %14, metadata !188, metadata !DIExpression()), !dbg !189
  br i1 %23, label %55, label %24, !dbg !179

24:                                               ; preds = %16
  %25 = load i8, i8* %14, align 4, !dbg !191
  %26 = shl i8 %25, 2, !dbg !193
  %27 = and i8 %26, 60, !dbg !193
  %28 = zext i8 %27 to i64
  %29 = getelementptr i8, i8* %14, i64 %28, !dbg !194
  %30 = icmp ugt i8* %29, %6, !dbg !195
  br i1 %30, label %55, label %31, !dbg !196

31:                                               ; preds = %24
  %32 = getelementptr i8, i8* %10, i64 23, !dbg !197
  %33 = load i8, i8* %32, align 1, !dbg !197, !tbaa !198
  call void @llvm.dbg.value(metadata i8 %33, metadata !139, metadata !DIExpression(DW_OP_LLVM_convert, 8, DW_ATE_unsigned, DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !141
  %34 = icmp ne i8 %33, 17
  %35 = getelementptr i8, i8* %29, i64 8
  %36 = icmp ugt i8* %35, %6
  %37 = select i1 %34, i1 true, i1 %36, !dbg !200
  br i1 %37, label %55, label %38, !dbg !200

38:                                               ; preds = %31
  call void @llvm.dbg.value(metadata i8* %29, metadata !129, metadata !DIExpression()), !dbg !141
  %39 = getelementptr inbounds i8, i8* %29, i64 2, !dbg !201
  %40 = bitcast i8* %39 to i16*, !dbg !201
  %41 = load i16, i16* %40, align 2, !dbg !201, !tbaa !203
  %42 = icmp eq i16 %41, 13568, !dbg !205
  br i1 %42, label %47, label %43, !dbg !206

43:                                               ; preds = %38
  call void @llvm.dbg.value(metadata i8* %29, metadata !129, metadata !DIExpression()), !dbg !141
  %44 = bitcast i8* %29 to i16*, !dbg !207
  %45 = load i16, i16* %44, align 2, !dbg !207, !tbaa !208
  %46 = icmp eq i16 %45, 13568, !dbg !209
  br i1 %46, label %47, label %55, !dbg !210

47:                                               ; preds = %43, %38
  call void @llvm.dbg.value(metadata i32* %2, metadata !140, metadata !DIExpression(DW_OP_deref)), !dbg !141
  %48 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i8* noundef bitcast (%struct.anon.1* @xsks_map to i8*), i8* noundef nonnull %11) #3, !dbg !211
  %49 = icmp eq i8* %48, null, !dbg !211
  br i1 %49, label %55, label %50, !dbg !214

50:                                               ; preds = %47
  %51 = load i32, i32* %2, align 4, !dbg !215, !tbaa !158
  call void @llvm.dbg.value(metadata i32 %51, metadata !140, metadata !DIExpression()), !dbg !141
  %52 = zext i32 %51 to i64, !dbg !215
  %53 = call i64 inttoptr (i64 51 to i64 (i8*, i64, i64)*)(i8* noundef bitcast (%struct.anon.1* @xsks_map to i8*), i64 noundef %52, i64 noundef 2) #3, !dbg !216
  %54 = trunc i64 %53 to i32, !dbg !216
  br label %55, !dbg !217

55:                                               ; preds = %24, %1, %43, %47, %31, %16, %50
  %56 = phi i32 [ %54, %50 ], [ 2, %16 ], [ 2, %31 ], [ 2, %47 ], [ 2, %43 ], [ 2, %1 ], [ 2, %24 ], !dbg !141
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %11) #3, !dbg !218
  ret i32 %56, !dbg !218
}

; Function Attrs: argmemonly mustprogress nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg, i8* nocapture) #1

; Function Attrs: argmemonly mustprogress nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg, i8* nocapture) #1

; Function Attrs: nofree nosync nounwind readnone speculatable willreturn
declare void @llvm.dbg.value(metadata, metadata, metadata) #2

attributes #0 = { nounwind "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" }
attributes #1 = { argmemonly mustprogress nofree nosync nounwind willreturn }
attributes #2 = { nofree nosync nounwind readnone speculatable willreturn }
attributes #3 = { nounwind }

!llvm.dbg.cu = !{!2}
!llvm.module.flags = !{!66, !67, !68, !69}
!llvm.ident = !{!70}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "xsks_map", scope: !2, file: !3, line: 15, type: !44, isLocal: false, isDefinition: true)
!2 = distinct !DICompileUnit(language: DW_LANG_C99, file: !3, producer: "Ubuntu clang version 14.0.0-1ubuntu1.1", isOptimized: true, runtimeVersion: 0, emissionKind: FullDebug, enums: !4, retainedTypes: !14, globals: !22, splitDebugInlining: false, nameTableKind: None)
!3 = !DIFile(filename: "dns_filter_kern.c", directory: "/home/quantumbits2/Documents/Python/cs331_cn/project/xdp-tutorial/aaaaa", checksumkind: CSK_MD5, checksum: "db181c0c6371a975adf63f7f276f8e94")
!4 = !{!5}
!5 = !DICompositeType(tag: DW_TAG_enumeration_type, name: "xdp_action", file: !6, line: 5447, baseType: !7, size: 32, elements: !8)
!6 = !DIFile(filename: "/usr/include/linux/bpf.h", directory: "", checksumkind: CSK_MD5, checksum: "e35b163ac757a706afe87c4e3c9d01d2")
!7 = !DIBasicType(name: "unsigned int", size: 32, encoding: DW_ATE_unsigned)
!8 = !{!9, !10, !11, !12, !13}
!9 = !DIEnumerator(name: "XDP_ABORTED", value: 0)
!10 = !DIEnumerator(name: "XDP_DROP", value: 1)
!11 = !DIEnumerator(name: "XDP_PASS", value: 2)
!12 = !DIEnumerator(name: "XDP_TX", value: 3)
!13 = !DIEnumerator(name: "XDP_REDIRECT", value: 4)
!14 = !{!15, !16, !17, !19}
!15 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: null, size: 64)
!16 = !DIBasicType(name: "long", size: 64, encoding: DW_ATE_signed)
!17 = !DIDerivedType(tag: DW_TAG_typedef, name: "__be16", file: !18, line: 25, baseType: !19)
!18 = !DIFile(filename: "/usr/include/linux/types.h", directory: "", checksumkind: CSK_MD5, checksum: "52ec79a38e49ac7d1dc9e146ba88a7b1")
!19 = !DIDerivedType(tag: DW_TAG_typedef, name: "__u16", file: !20, line: 24, baseType: !21)
!20 = !DIFile(filename: "/usr/include/asm-generic/int-ll64.h", directory: "", checksumkind: CSK_MD5, checksum: "b810f270733e106319b67ef512c6246e")
!21 = !DIBasicType(name: "unsigned short", size: 16, encoding: DW_ATE_unsigned)
!22 = !{!23, !0, !29, !37}
!23 = !DIGlobalVariableExpression(var: !24, expr: !DIExpression())
!24 = distinct !DIGlobalVariable(name: "_license", scope: !2, file: !3, line: 94, type: !25, isLocal: false, isDefinition: true)
!25 = !DICompositeType(tag: DW_TAG_array_type, baseType: !26, size: 32, elements: !27)
!26 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!27 = !{!28}
!28 = !DISubrange(count: 4)
!29 = !DIGlobalVariableExpression(var: !30, expr: !DIExpression())
!30 = distinct !DIGlobalVariable(name: "bpf_map_lookup_elem", scope: !2, file: !31, line: 56, type: !32, isLocal: true, isDefinition: true)
!31 = !DIFile(filename: "../lib/install/include/bpf/bpf_helper_defs.h", directory: "/home/quantumbits2/Documents/Python/cs331_cn/project/xdp-tutorial/aaaaa", checksumkind: CSK_MD5, checksum: "7422ca06c9dc86eba2f268a57d8acf2f")
!32 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !33, size: 64)
!33 = !DISubroutineType(types: !34)
!34 = !{!15, !15, !35}
!35 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !36, size: 64)
!36 = !DIDerivedType(tag: DW_TAG_const_type, baseType: null)
!37 = !DIGlobalVariableExpression(var: !38, expr: !DIExpression())
!38 = distinct !DIGlobalVariable(name: "bpf_redirect_map", scope: !2, file: !31, line: 1323, type: !39, isLocal: true, isDefinition: true)
!39 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !40, size: 64)
!40 = !DISubroutineType(types: !41)
!41 = !{!16, !15, !42, !42}
!42 = !DIDerivedType(tag: DW_TAG_typedef, name: "__u64", file: !20, line: 31, baseType: !43)
!43 = !DIBasicType(name: "unsigned long long", size: 64, encoding: DW_ATE_unsigned)
!44 = distinct !DICompositeType(tag: DW_TAG_structure_type, file: !3, line: 9, size: 320, elements: !45)
!45 = !{!46, !52, !55, !56, !61}
!46 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !44, file: !3, line: 10, baseType: !47, size: 64)
!47 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !48, size: 64)
!48 = !DICompositeType(tag: DW_TAG_array_type, baseType: !49, size: 544, elements: !50)
!49 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!50 = !{!51}
!51 = !DISubrange(count: 17)
!52 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !44, file: !3, line: 11, baseType: !53, size: 64, offset: 64)
!53 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !54, size: 64)
!54 = !DIDerivedType(tag: DW_TAG_typedef, name: "__u32", file: !20, line: 27, baseType: !7)
!55 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !44, file: !3, line: 12, baseType: !53, size: 64, offset: 128)
!56 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !44, file: !3, line: 13, baseType: !57, size: 64, offset: 192)
!57 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !58, size: 64)
!58 = !DICompositeType(tag: DW_TAG_array_type, baseType: !49, size: 2048, elements: !59)
!59 = !{!60}
!60 = !DISubrange(count: 64)
!61 = !DIDerivedType(tag: DW_TAG_member, name: "pinning", scope: !44, file: !3, line: 14, baseType: !62, size: 64, offset: 256)
!62 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !63, size: 64)
!63 = !DICompositeType(tag: DW_TAG_array_type, baseType: !49, size: 32, elements: !64)
!64 = !{!65}
!65 = !DISubrange(count: 1)
!66 = !{i32 7, !"Dwarf Version", i32 5}
!67 = !{i32 2, !"Debug Info Version", i32 3}
!68 = !{i32 1, !"wchar_size", i32 4}
!69 = !{i32 7, !"frame-pointer", i32 2}
!70 = !{!"Ubuntu clang version 14.0.0-1ubuntu1.1"}
!71 = distinct !DISubprogram(name: "xdp_dns_filter_func", scope: !3, file: !3, line: 56, type: !72, scopeLine: 57, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !83)
!72 = !DISubroutineType(types: !73)
!73 = !{!49, !74}
!74 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !75, size: 64)
!75 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "xdp_md", file: !6, line: 5458, size: 192, elements: !76)
!76 = !{!77, !78, !79, !80, !81, !82}
!77 = !DIDerivedType(tag: DW_TAG_member, name: "data", scope: !75, file: !6, line: 5459, baseType: !54, size: 32)
!78 = !DIDerivedType(tag: DW_TAG_member, name: "data_end", scope: !75, file: !6, line: 5460, baseType: !54, size: 32, offset: 32)
!79 = !DIDerivedType(tag: DW_TAG_member, name: "data_meta", scope: !75, file: !6, line: 5461, baseType: !54, size: 32, offset: 64)
!80 = !DIDerivedType(tag: DW_TAG_member, name: "ingress_ifindex", scope: !75, file: !6, line: 5463, baseType: !54, size: 32, offset: 96)
!81 = !DIDerivedType(tag: DW_TAG_member, name: "rx_queue_index", scope: !75, file: !6, line: 5464, baseType: !54, size: 32, offset: 128)
!82 = !DIDerivedType(tag: DW_TAG_member, name: "egress_ifindex", scope: !75, file: !6, line: 5466, baseType: !54, size: 32, offset: 160)
!83 = !{!84, !85, !86, !87, !99, !129, !138, !139, !140}
!84 = !DILocalVariable(name: "ctx", arg: 1, scope: !71, file: !3, line: 56, type: !74)
!85 = !DILocalVariable(name: "data_end", scope: !71, file: !3, line: 58, type: !15)
!86 = !DILocalVariable(name: "data", scope: !71, file: !3, line: 59, type: !15)
!87 = !DILocalVariable(name: "eth", scope: !71, file: !3, line: 60, type: !88)
!88 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !89, size: 64)
!89 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "ethhdr", file: !90, line: 168, size: 112, elements: !91)
!90 = !DIFile(filename: "/usr/include/linux/if_ether.h", directory: "", checksumkind: CSK_MD5, checksum: "ab0320da726e75d904811ce344979934")
!91 = !{!92, !97, !98}
!92 = !DIDerivedType(tag: DW_TAG_member, name: "h_dest", scope: !89, file: !90, line: 169, baseType: !93, size: 48)
!93 = !DICompositeType(tag: DW_TAG_array_type, baseType: !94, size: 48, elements: !95)
!94 = !DIBasicType(name: "unsigned char", size: 8, encoding: DW_ATE_unsigned_char)
!95 = !{!96}
!96 = !DISubrange(count: 6)
!97 = !DIDerivedType(tag: DW_TAG_member, name: "h_source", scope: !89, file: !90, line: 170, baseType: !93, size: 48, offset: 48)
!98 = !DIDerivedType(tag: DW_TAG_member, name: "h_proto", scope: !89, file: !90, line: 171, baseType: !17, size: 16, offset: 96)
!99 = !DILocalVariable(name: "iph", scope: !71, file: !3, line: 61, type: !100)
!100 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !101, size: 64)
!101 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "iphdr", file: !102, line: 87, size: 160, elements: !103)
!102 = !DIFile(filename: "/usr/include/linux/ip.h", directory: "", checksumkind: CSK_MD5, checksum: "042b09a58768855e3578a0a8eba49be7")
!103 = !{!104, !106, !107, !108, !109, !110, !111, !112, !113, !115}
!104 = !DIDerivedType(tag: DW_TAG_member, name: "ihl", scope: !101, file: !102, line: 89, baseType: !105, size: 4, flags: DIFlagBitField, extraData: i64 0)
!105 = !DIDerivedType(tag: DW_TAG_typedef, name: "__u8", file: !20, line: 21, baseType: !94)
!106 = !DIDerivedType(tag: DW_TAG_member, name: "version", scope: !101, file: !102, line: 90, baseType: !105, size: 4, offset: 4, flags: DIFlagBitField, extraData: i64 0)
!107 = !DIDerivedType(tag: DW_TAG_member, name: "tos", scope: !101, file: !102, line: 97, baseType: !105, size: 8, offset: 8)
!108 = !DIDerivedType(tag: DW_TAG_member, name: "tot_len", scope: !101, file: !102, line: 98, baseType: !17, size: 16, offset: 16)
!109 = !DIDerivedType(tag: DW_TAG_member, name: "id", scope: !101, file: !102, line: 99, baseType: !17, size: 16, offset: 32)
!110 = !DIDerivedType(tag: DW_TAG_member, name: "frag_off", scope: !101, file: !102, line: 100, baseType: !17, size: 16, offset: 48)
!111 = !DIDerivedType(tag: DW_TAG_member, name: "ttl", scope: !101, file: !102, line: 101, baseType: !105, size: 8, offset: 64)
!112 = !DIDerivedType(tag: DW_TAG_member, name: "protocol", scope: !101, file: !102, line: 102, baseType: !105, size: 8, offset: 72)
!113 = !DIDerivedType(tag: DW_TAG_member, name: "check", scope: !101, file: !102, line: 103, baseType: !114, size: 16, offset: 80)
!114 = !DIDerivedType(tag: DW_TAG_typedef, name: "__sum16", file: !18, line: 31, baseType: !19)
!115 = !DIDerivedType(tag: DW_TAG_member, scope: !101, file: !102, line: 104, baseType: !116, size: 64, offset: 96)
!116 = distinct !DICompositeType(tag: DW_TAG_union_type, scope: !101, file: !102, line: 104, size: 64, elements: !117)
!117 = !{!118, !124}
!118 = !DIDerivedType(tag: DW_TAG_member, scope: !116, file: !102, line: 104, baseType: !119, size: 64)
!119 = distinct !DICompositeType(tag: DW_TAG_structure_type, scope: !116, file: !102, line: 104, size: 64, elements: !120)
!120 = !{!121, !123}
!121 = !DIDerivedType(tag: DW_TAG_member, name: "saddr", scope: !119, file: !102, line: 104, baseType: !122, size: 32)
!122 = !DIDerivedType(tag: DW_TAG_typedef, name: "__be32", file: !18, line: 27, baseType: !54)
!123 = !DIDerivedType(tag: DW_TAG_member, name: "daddr", scope: !119, file: !102, line: 104, baseType: !122, size: 32, offset: 32)
!124 = !DIDerivedType(tag: DW_TAG_member, name: "addrs", scope: !116, file: !102, line: 104, baseType: !125, size: 64)
!125 = distinct !DICompositeType(tag: DW_TAG_structure_type, scope: !116, file: !102, line: 104, size: 64, elements: !126)
!126 = !{!127, !128}
!127 = !DIDerivedType(tag: DW_TAG_member, name: "saddr", scope: !125, file: !102, line: 104, baseType: !122, size: 32)
!128 = !DIDerivedType(tag: DW_TAG_member, name: "daddr", scope: !125, file: !102, line: 104, baseType: !122, size: 32, offset: 32)
!129 = !DILocalVariable(name: "udph", scope: !71, file: !3, line: 62, type: !130)
!130 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !131, size: 64)
!131 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "udphdr", file: !132, line: 23, size: 64, elements: !133)
!132 = !DIFile(filename: "/usr/include/linux/udp.h", directory: "", checksumkind: CSK_MD5, checksum: "53c0d42e1bf6d93b39151764be2d20fb")
!133 = !{!134, !135, !136, !137}
!134 = !DIDerivedType(tag: DW_TAG_member, name: "source", scope: !131, file: !132, line: 24, baseType: !17, size: 16)
!135 = !DIDerivedType(tag: DW_TAG_member, name: "dest", scope: !131, file: !132, line: 25, baseType: !17, size: 16, offset: 16)
!136 = !DIDerivedType(tag: DW_TAG_member, name: "len", scope: !131, file: !132, line: 26, baseType: !17, size: 16, offset: 32)
!137 = !DIDerivedType(tag: DW_TAG_member, name: "check", scope: !131, file: !132, line: 27, baseType: !114, size: 16, offset: 48)
!138 = !DILocalVariable(name: "eth_type", scope: !71, file: !3, line: 63, type: !49)
!139 = !DILocalVariable(name: "ip_type", scope: !71, file: !3, line: 63, type: !49)
!140 = !DILocalVariable(name: "index", scope: !71, file: !3, line: 64, type: !54)
!141 = !DILocation(line: 0, scope: !71)
!142 = !DILocation(line: 58, column: 41, scope: !71)
!143 = !{!144, !145, i64 4}
!144 = !{!"xdp_md", !145, i64 0, !145, i64 4, !145, i64 8, !145, i64 12, !145, i64 16, !145, i64 20}
!145 = !{!"int", !146, i64 0}
!146 = !{!"omnipotent char", !147, i64 0}
!147 = !{!"Simple C/C++ TBAA"}
!148 = !DILocation(line: 58, column: 30, scope: !71)
!149 = !DILocation(line: 58, column: 22, scope: !71)
!150 = !DILocation(line: 59, column: 37, scope: !71)
!151 = !{!144, !145, i64 0}
!152 = !DILocation(line: 59, column: 26, scope: !71)
!153 = !DILocation(line: 59, column: 18, scope: !71)
!154 = !DILocation(line: 64, column: 5, scope: !71)
!155 = !DILocation(line: 64, column: 24, scope: !71)
!156 = !{!144, !145, i64 16}
!157 = !DILocation(line: 64, column: 11, scope: !71)
!158 = !{!145, !145, i64 0}
!159 = !DILocalVariable(name: "data", arg: 1, scope: !160, file: !3, line: 18, type: !163)
!160 = distinct !DISubprogram(name: "parse_ethhdr", scope: !3, file: !3, line: 18, type: !161, scopeLine: 19, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !165)
!161 = !DISubroutineType(types: !162)
!162 = !{!49, !163, !15, !164}
!163 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !15, size: 64)
!164 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !88, size: 64)
!165 = !{!159, !166, !167, !168}
!166 = !DILocalVariable(name: "data_end", arg: 2, scope: !160, file: !3, line: 18, type: !15)
!167 = !DILocalVariable(name: "eth", arg: 3, scope: !160, file: !3, line: 18, type: !164)
!168 = !DILocalVariable(name: "eth_hdr", scope: !160, file: !3, line: 20, type: !88)
!169 = !DILocation(line: 0, scope: !160, inlinedAt: !170)
!170 = distinct !DILocation(line: 67, column: 16, scope: !71)
!171 = !DILocation(line: 21, column: 25, scope: !172, inlinedAt: !170)
!172 = distinct !DILexicalBlock(scope: !160, file: !3, line: 21, column: 9)
!173 = !DILocation(line: 21, column: 44, scope: !172, inlinedAt: !170)
!174 = !DILocation(line: 21, column: 9, scope: !160, inlinedAt: !170)
!175 = !DILocation(line: 26, column: 12, scope: !160, inlinedAt: !170)
!176 = !{!177, !178, i64 12}
!177 = !{!"ethhdr", !146, i64 0, !146, i64 6, !178, i64 12}
!178 = !{!"short", !146, i64 0}
!179 = !DILocation(line: 68, column: 9, scope: !71)
!180 = !DILocalVariable(name: "data", arg: 1, scope: !181, file: !3, line: 29, type: !163)
!181 = distinct !DISubprogram(name: "parse_iphdr", scope: !3, file: !3, line: 29, type: !182, scopeLine: 30, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !185)
!182 = !DISubroutineType(types: !183)
!183 = !{!49, !163, !15, !184}
!184 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !100, size: 64)
!185 = !{!180, !186, !187, !188}
!186 = !DILocalVariable(name: "data_end", arg: 2, scope: !181, file: !3, line: 29, type: !15)
!187 = !DILocalVariable(name: "iph", arg: 3, scope: !181, file: !3, line: 29, type: !184)
!188 = !DILocalVariable(name: "ip_hdr", scope: !181, file: !3, line: 31, type: !100)
!189 = !DILocation(line: 0, scope: !181, inlinedAt: !190)
!190 = distinct !DILocation(line: 74, column: 15, scope: !71)
!191 = !DILocation(line: 36, column: 35, scope: !192, inlinedAt: !190)
!192 = distinct !DILexicalBlock(scope: !181, file: !3, line: 36, column: 9)
!193 = !DILocation(line: 36, column: 39, scope: !192, inlinedAt: !190)
!194 = !DILocation(line: 36, column: 24, scope: !192, inlinedAt: !190)
!195 = !DILocation(line: 36, column: 44, scope: !192, inlinedAt: !190)
!196 = !DILocation(line: 36, column: 9, scope: !181, inlinedAt: !190)
!197 = !DILocation(line: 41, column: 20, scope: !181, inlinedAt: !190)
!198 = !{!199, !146, i64 9}
!199 = !{!"iphdr", !146, i64 0, !146, i64 0, !146, i64 1, !178, i64 2, !178, i64 4, !178, i64 6, !146, i64 8, !146, i64 9, !178, i64 10, !146, i64 12}
!200 = !DILocation(line: 75, column: 9, scope: !71)
!201 = !DILocation(line: 85, column: 9, scope: !202)
!202 = distinct !DILexicalBlock(scope: !71, file: !3, line: 85, column: 9)
!203 = !{!204, !178, i64 2}
!204 = !{!"udphdr", !178, i64 0, !178, i64 2, !178, i64 4, !178, i64 6}
!205 = !DILocation(line: 85, column: 38, scope: !202)
!206 = !DILocation(line: 85, column: 44, scope: !202)
!207 = !DILocation(line: 85, column: 47, scope: !202)
!208 = !{!204, !178, i64 0}
!209 = !DILocation(line: 85, column: 78, scope: !202)
!210 = !DILocation(line: 85, column: 9, scope: !71)
!211 = !DILocation(line: 87, column: 13, scope: !212)
!212 = distinct !DILexicalBlock(scope: !213, file: !3, line: 87, column: 13)
!213 = distinct !DILexicalBlock(scope: !202, file: !3, line: 85, column: 85)
!214 = !DILocation(line: 87, column: 13, scope: !213)
!215 = !DILocation(line: 88, column: 48, scope: !212)
!216 = !DILocation(line: 88, column: 20, scope: !212)
!217 = !DILocation(line: 88, column: 13, scope: !212)
!218 = !DILocation(line: 92, column: 1, scope: !71)
