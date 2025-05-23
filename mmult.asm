

            .data
N:          .word 4

# A (row-major)
A:          .word  1,  2,  3,  4
            .word  5,  6,  7,  8
            .word  9, 10, 11, 12
            .word 13, 14, 15, 16

# B (row-major)
B:          .word 16, 15, 14, 13
            .word 12, 11, 10,  9
            .word  8,  7,  6,  5
            .word  4,  3,  2,  1

C:          .space 64            # 4 × 4 results

            .text
# ---------------------------------------------------------------------------
#  Register map
#     $t0  n (4)          $t1  i          $t2  j          $t3  k-counter
#     $t4  sum            $t5  ptrA       $t6  ptrB       $t7  Aelem
#     $t8  Belem          $t9  product    $s6  mult_cnt
#     $s0  baseA          $s1  baseB      $s2  baseC
#     $s3  ptrArow        $s4  ptrCrow    $s5  ptrBstart  $s7  ptrCcol
# ---------------------------------------------------------------------------

            # --- load n and base addresses -------------------------
            la    $t5, N
            lw    $t0, 0($t5)        # n = 4

            la    $s0, A
            la    $s1, B
            la    $s2, C

            addiu $s3, $s0, 0        # ptrArow  = baseA
            addiu $s4, $s2, 0        # ptrCrow  = baseC
            addiu $t1, $zero, 0      # i = 0

            # -------- ROI BEGIN ------------------------------------
            addiu $v0, $zero, 88
            syscall

outer_i:    beq   $t1, $t0, done_outer     # if i == n -> exit

            # j initialisation
            addiu $t2, $zero, 0            # j = 0
            addiu $s5, $s1, 0              # ptrBstart = baseB
            addiu $s7, $s4, 0              # ptrCcol   = ptrCrow

outer_j:    beq   $t2, $t0, next_i         # if j == n -> next row

            # ----- init inner-loop state ---------------------------
            addiu $t4, $zero, 0            # sum = 0
            addiu $t3, $t0, 0              # k = n
            addiu $t5, $s3, 0              # ptrA = ptrArow
            addiu $t6, $s5, 0              # ptrB = ptrBstart

inner_k:    # load A[i,k] and B[k,j]
            lw    $t7, 0($t5)
            lw    $t8, 0($t6)

            # ----- product = Aelem * Belem (repeated add) ----------
            addiu $t9, $zero, 0            # product = 0
            addiu $s6, $t8, 0              # mult_cnt = Belem
mult_loop:  beq   $s6, $zero, mult_done
            addu  $t9, $t9, $t7
            addiu $s6, $s6, -1
            bne   $s6, $zero, mult_loop
mult_done:

            # sum += product
            addu  $t4, $t4, $t9

            # advance A row ptr, B column ptr, k--
            addiu $t5, $t5, 4              # ptrA += 4
            addiu $t6, $t6, 16             # ptrB += row-stride (4 words)
            addiu $t3, $t3, -1
            bne   $t3, $zero, inner_k

            # ----- store C[i,j] ------------------------------------
            sw    $t4, 0($s7)

            # advance column pointers
            addiu $s7, $s7, 4              # ptrCcol   += 4
            addiu $s5, $s5, 4              # ptrBstart += 4
            addiu $t2, $t2, 1              # j++

            bne   $t2, $t0, outer_j

next_i:     addiu $t1, $t1, 1              # i++
            addiu $s3, $s3, 16             # ptrArow += 16 bytes (4 words)
            addiu $s4, $s4, 16             # ptrCrow += 16 bytes
            j     outer_i

done_outer:
            # -------- ROI END --------------------------------------
            addiu $v0, $zero, 88
            syscall


            addiu $v0, $zero, 10
            syscall

