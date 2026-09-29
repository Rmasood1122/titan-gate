library(testthat)
library(titangate)

TV1 <- '../../../../tests/vectors/TV1.json'
TV2 <- '../../../../tests/vectors/TV2.json'
TV3 <- '../../../../tests/vectors/TV3.json'
GOOD_KEY <- paste(rep('0', 64), collapse = '')
BAD_KEY <- paste(rep('f', 64), collapse = '')

test_that('TV1 verifies as VALID', {
  result <- verify_receipt(TV1, GOOD_KEY)
  expect_true(result[['ok']])
})

test_that('TV2 verifies as VALID', {
  result <- verify_receipt(TV2, GOOD_KEY)
  expect_true(result[['ok']])
})

test_that('TV3 verifies as VALID', {
  result <- verify_receipt(TV3, GOOD_KEY)
  expect_true(result[['ok']])
})

test_that('wrong key fails', {
  result <- verify_receipt(TV1, BAD_KEY)
  expect_false(isTRUE(result[['ok']]))
})

test_that('chain_verify passes all three vectors', {
  result <- chain_verify(c(TV1, TV2, TV3), GOOD_KEY)
  expect_true(result[['ok']])
  expect_equal(result[['count']], 3)
})
