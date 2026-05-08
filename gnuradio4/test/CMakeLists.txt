function(gr_openssl4_add_ut name)
  add_executable(${name} ${name}.cpp)
  target_link_libraries(${name} PRIVATE gnuradio4::gnuradio-options gnuradio4::gnuradio-core gnuradio4::gnuradio-blocklib-core
                                          gnuradio4::gr-openssl ut)
  add_test(NAME ${name} COMMAND ${CMAKE_CROSSCOMPILING_EMULATOR} $<TARGET_FILE:${name}>)
endfunction()

gr_openssl4_add_ut(qa_SymEnc)
gr_openssl4_add_ut(qa_SymDec)
gr_openssl4_add_ut(qa_Hash)
gr_openssl4_add_ut(qa_AuthEncAesGcm)
gr_openssl4_add_ut(qa_AuthDecAesGcm)
gr_openssl4_add_ut(qa_SymEncTaggedBb)
gr_openssl4_add_ut(qa_SymDecTaggedBb)
