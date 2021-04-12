function(version_config project major minor patch rc)
  set(V "v${major}.${minor}.${patch}")
  if(rc)
    string(JOIN - V "${V}" "${rc}")
  endif()
  set("${project}_VERSION" "${V}" PARENT_SCOPE)
  set("${project}_VERSION_DEFINITIONS" "${project}_VERSION=\"${V}\"" PARENT_SCOPE)
endfunction()
