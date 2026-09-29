check_cli <- function() {
  result <- system2('titan-verify', args = '--version', stdout = TRUE, stderr = TRUE)
  status <- attr(result, 'status')
  if (is.null(status) || status == 0) {
    message('titan-verify is available: ', paste(result, collapse = ' '))
    return(invisible(TRUE))
  }
  message('titan-verify not found. Install with: pip install titan-gate')
  return(invisible(FALSE))
}
