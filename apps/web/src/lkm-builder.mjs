/**
 * Linux LKM lab helpers (client side).
 *
 * The linux track compiles INSIDE the guest: buildroot ships gcc and the
 * prepared kernel build tree, so the browser only validates the source,
 * ships it into the guest over the 9p mount, and drives the canonical
 * build+insmod sequence over the serial console.
 */

/** Client-side source sanity before shipping into the guest. */
export function validateLinuxSource(source) {
  const errors = [];
  if (!source || !source.trim()) errors.push("empty module source");
  if (!/#include\s*<linux\/module\.h>/.test(source)) {
    errors.push('missing #include <linux/module.h>');
  }
  if (!/module_init\s*\(/.test(source)) {
    errors.push("no module_init() — the kernel has no idea where to start");
  }
  if (!/MODULE_LICENSE\s*\(/.test(source)) {
    errors.push("missing MODULE_LICENSE() — taints the kernel and blocks loading");
  }
  if (/ntddk\.h|windows\.h/i.test(source)) {
    errors.push("Windows headers in a Linux module — wrong track?");
  }
  return { ok: errors.length === 0, errors };
}

/**
 * Canonical guest-side sequence for building + loading a student module.
 * Sent line-by-line via V86LabSession.sendLine().
 * @param {string} name module base name, e.g. "kflag"
 */
export function guestBuildSequence(name) {
  const KDIR = "/lib/modules/$(uname -r)/build";
  return [
    `cd /root/lab`,
    `${name}.c`, // file already injected; nothing to do for it
    `gcc -O2 -c ${name}.c -o ${name}.o -I${KDIR}/include -I${KDIR}/arch/x86/include -D__KERNEL__`,
    `insmod ${name}.o || insmod ./${name}.o`,
    `dmesg | tail -20`,
  ].filter((l) => !/^\S+\.c$/.test(l));
}
