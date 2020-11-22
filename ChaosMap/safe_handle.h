#pragma once
#include <windows.h>
#include <utility>

class safe_handle
{
public:
	safe_handle() : m_handle(nullptr) {}
	explicit safe_handle(HANDLE new_handle) noexcept : m_handle(new_handle) {}
	~safe_handle() noexcept
	{
		if (this->unsafe_handle())
		{
			//logger::log_formatted("Closing", this->handle, true);
			CloseHandle(this->unsafe_handle());
		}
	}

	safe_handle(const safe_handle& that) = delete;

	safe_handle& operator= (const safe_handle& other) = delete;

	safe_handle(safe_handle&& other) noexcept : m_handle(other.m_handle)
	{
		other.invalidate();
	} 

	safe_handle& operator= (safe_handle&& other) noexcept 
	{
		this->m_handle = other.m_handle;
		other.invalidate();
		return *this;
	}

	explicit operator bool() const noexcept
	{
		return this->unsafe_handle() != nullptr;
	}

	inline auto unsafe_handle() const noexcept -> const HANDLE&
	{
		return this->m_handle;
	}

	inline auto invalidate() noexcept -> void
	{
		this->m_handle = nullptr;
	}

private:
	HANDLE m_handle;
};