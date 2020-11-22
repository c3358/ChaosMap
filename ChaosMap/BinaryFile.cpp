#include "BinaryFile.h"
#include "Logger.h"
#include <vector>
#include <fstream>

binary_file::binary_file(std::string_view file_path)
{
	std::ifstream stream(file_path.data(), std::ios::binary);

	stream.unsetf(std::ios::skipws);

	stream.seekg(0, std::ios::end);		
	const auto length = stream.tellg();	
	stream.seekg(0, std::ios::beg);		

	if (length == -1)
		return;

	this->m_buffer = std::vector<std::byte>(length);

	stream.read(reinterpret_cast<char*>(this->m_buffer.data()), length);
}

const std::vector<std::byte>& binary_file::buffer() const noexcept
{
	return this->m_buffer;
}
