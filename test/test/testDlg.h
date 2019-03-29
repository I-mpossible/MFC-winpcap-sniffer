
// testDlg.h: 头文件
//

#pragma once


// CtestDlg 对话框
class CtestDlg : public CDialogEx
{
// 构造
public:
	CtestDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_TEST_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持
	

// 实现
protected:
	HICON m_hIcon;
	CWinThread * myWinThread;
	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()



public:
	CButton m_start;
	CTreeCtrl m_tree;
	CButton m_stop;
	CListCtrl m_listctl1;
	CComboBox m_devlist;
	afx_msg void OnBnClickedButton2();
	afx_msg void OnBnClickedButton1();
	afx_msg void OnLvnItemchangedList1(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnCbnSelchangeCombo1();
	afx_msg void OnNMCustomdrawList1(NMHDR *pNMHDR, LRESULT *pResult);
	CComboBox m_protocol;
	afx_msg void OnNMClickList1(NMHDR *pNMHDR, LRESULT *pResult);
};
