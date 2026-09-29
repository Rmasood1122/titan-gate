verify_receipt <- function(receipt_path, key_hex, format = 'json') {
  result <- system2('titan-verify', args = c(receipt_path, '--key', key_hex, '--format', format), stdout = TRUE, stderr = TRUE)
  status <- attr(result, 'status')
  if (is.null(status)) status <- 0
  output <- paste(result, collapse = '\n')
  if (format == 'json') {
    parsed <- tryCatch(jsonlite::fromJSON(output), error = function(e) list(ok = FALSE, message = as.character(e)))
    parsed[['exit_code']] <- status
    return(parsed)
  }
  list(ok = (status == 0), output = output, exit_code = status)
}

chain_verify <- function(receipt_paths, key_hex) {
  results <- lapply(receipt_paths, function(p) verify_receipt(p, key_hex))
  all_ok <- all(sapply(results, function(r) isTRUE(r[['ok']])))
  list(ok = all_ok, results = results, count = length(results))
}
